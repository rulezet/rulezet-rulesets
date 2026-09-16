import "pe"
rule _624_10_
{
	meta:
		description = "624 1.0"
	strings:
		$0 = {50 55 4C 50 83 C4 07 FC BF 00 80 BE 14 01 B5 30 57 F3 A5 C3 33 ED BE 6C 80 BF 00 01 57 81 FF 00 00 73 42 E8 3B 00 72 0A B1 08 99 E8 46 00 93 AA EB EB B2 08 E8 2A 00 73 09 41 4A 75 F7 E8 26 00 8B CB E3 10 51 E8 1E 00 59 56 8B F7 2B F3 41 F3}
	condition:
		$0 at pe.entry_point
}