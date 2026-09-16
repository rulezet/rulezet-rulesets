import "pe"
rule pe_resource_single_byte_xor_PE : hardened
{
	meta:
		description = "Try the 3rd byte as a XOR key, since typically that byte is zero in a PE, meaning in encoded form it will contain the XOR key"

	condition:
		pe.is_pe and for any resource in pe.resources : ( uint16( resource.offset ) != 0x5a4d and uint8( resource.offset ) ^ uint8( resource.offset + 3 ) == 0x4d and uint8( resource.offset + 1 ) ^ uint8( resource.offset + 3 ) == 0x5a )
}