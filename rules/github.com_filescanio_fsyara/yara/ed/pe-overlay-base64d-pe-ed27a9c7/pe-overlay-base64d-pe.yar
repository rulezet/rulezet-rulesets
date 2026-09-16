import "pe"
rule pe_overlay_base64d_pe : hardened
{
	meta:
		description = "looking for probable base64 encoded PE headers in the overlay"
		score = 75

	condition:
		pe.is_pe and pe.overlay.offset != 0x0 and uint32be( pe.overlay.offset ) == 0x54567151 and uint32be( pe.overlay.offset + 4 ) == 0x41414D41
}