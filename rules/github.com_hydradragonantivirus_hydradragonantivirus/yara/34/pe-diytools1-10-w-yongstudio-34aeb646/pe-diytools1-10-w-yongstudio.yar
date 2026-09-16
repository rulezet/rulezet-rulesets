rule PE_DIYTools1_10__W_YongStudio
{
	meta:
		author = "PEiD"
		description = "PE-DIY Tools 1.10 -> W-Yong Studio"
		group = "Auto"
		function = "0"
	strings:
		$a0 = { E8 00 00 00 00 5D 81 ED ?? ?? 40 00 8B 85 ?? ?? 40 00 FF 10 8B 85 ?? ?? 40 00 FF E0 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 }
	condition:
		$a0
}