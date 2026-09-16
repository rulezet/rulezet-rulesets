rule peidb102dll
{
	meta:
		author = "PEiD"
		description = "PEiD-Bundle 1.02 DLL -> BoB / Team PEiD"
		group = "2003"
		function = "0"
	strings:
		$a0 = { 83 7C 24 08 01 0F 85 ?? ?? ?? ?? 60 E8 9C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 41 00 08 00 39 00 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00 }
	condition:
		$a0
}