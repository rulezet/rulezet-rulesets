rule svkp11
{
	meta:
		author = "PEiD"
		description = "SVKP 1.11 -> Pavol Cerven"
		group = "178"
		function = "0"
	strings:
		$a0 = { 60 E8 ?? ?? ?? ?? 5D 81 ED 06 ?? ?? ?? 64 A0 23 }
	condition:
		$a0
}