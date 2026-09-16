rule simupx_single
{
	meta:
		author = "PEiD"
		description = "Simple UPX Cryptor 30.4.2005 [Single Layer] -> MANtiCORE"
		group = "999"
		function = "0"
	strings:
		$a0 = { 60 B8 ?? ?? ?? 00 B9 ?? 01 00 00 80 34 08 ?? E2 FA 61 68 ?? ?? ?? 00 C3 }
	condition:
		$a0
}