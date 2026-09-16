import "pe"
rule _PEBundle_005_
{
	meta:
		description = "PEBundle 0.05"
	strings:
		$0 = {9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 20 40 00 87 DD 01 AD CD 24 40 00 01 AD 41 25 40 00 01 AD 95 25 40 00 01 AD F0 25 40 00 01 AD 27 26 40 00 E8 FD 01 00 00 FF B5 A6 20 40 00 FF B5 08 21 40 00 E8 7F 02 00 00}
	condition:
		$0 at pe.entry_point
}