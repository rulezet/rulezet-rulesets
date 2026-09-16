import "pe"
rule upx_eclipse
{
	meta:
		author = "PEiD"
		description = "UPX + ECLiPSE layer -> TEAM ECLiPSE"
		group = "184"
		function = "0"
	strings:
		$a0 = { B8 ?? ?? ?? ?? B9 ?? ?? ?? ?? 33 D2 EB 01 0F 56 EB 01 0F E8 03 ?? ?? ?? EB 01 0F EB 01 0F 5E EB 01 }
	condition:
		$a0 at pe.entry_point
}