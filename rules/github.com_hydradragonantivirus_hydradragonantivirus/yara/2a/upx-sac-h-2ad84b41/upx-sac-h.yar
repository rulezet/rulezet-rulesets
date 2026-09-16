import "pe"
rule upx_sac_h
{
	meta:
		author = "PEiD"
		description = "UPX modified stub -> SAC/uNPACKinG gODS"
		group = "183"
		function = "0"
	strings:
		$a0 = { 79 07 0F B7 07 47 50 47 B9 57 48 F2 AE 55 FF 96 84 ?? ?? ?? 09 C0 74 07 89 03 83 C3 04 EB D8 FF 96 88 ?? ?? ?? 61 E9 ?? ?? ?? FF }
	condition:
		$a0 at pe.entry_point
}