import "pe"
rule pe_overlay_reversed_pe : hardened
{
	meta:
		description = "check for MZ at the end of the of the overlay"
		score = 75

	condition:
		pe.is_pe and pe.overlay.offset != 0x0 and uint16be( ( pe.overlay.offset + pe.overlay.size ) - 2 ) == 0x5a4d
}