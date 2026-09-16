rule ms_vc72
{
	meta:
		author = "PEiD"
		description = "Microsoft Visual C++ 7.0 Method2"
		group = "15"
		function = "25"
	strings:
		$a0 = { 6A ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? 00 33 DB }
	condition:
		$a0
}