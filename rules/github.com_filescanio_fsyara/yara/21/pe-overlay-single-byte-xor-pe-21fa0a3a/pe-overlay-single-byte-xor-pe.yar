import "pe"
rule pe_overlay_single_byte_xor_PE : hardened
{
	meta:
		description = "Try the 3rd byte as a XOR key, since typically that byte is zero in a PE, meaning in encoded form it will contain the XOR key"
		score = 75

	condition:
		pe.is_pe and pe.overlay.offset != 0x0 and uint16( pe.overlay.offset ) != 0x5a4d and int8 ( pe.overlay.offset ) ^ uint8( pe.overlay.offset + 3 ) == 0x4d and uint8( pe.overlay.offset + 1 ) ^ uint8( pe.overlay.offset + 3 ) == 0x5a
}