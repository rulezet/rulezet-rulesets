rule peb20x_BoB
{
	meta:
		author = "PEiD"
		description = "PEBundle 2.0x - 2.4x-> Jeremy Collake"
		group = "BoB"
		function = "0"
	strings:
		$a0 = { 9C 60 E8 02 ?? ?? ?? 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB ?? ?? 40 ?? 87 DD 83 BD }
	condition:
		$a0
}