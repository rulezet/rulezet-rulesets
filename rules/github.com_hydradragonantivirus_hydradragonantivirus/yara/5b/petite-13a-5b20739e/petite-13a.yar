import "pe"
rule _Petite_13a_
{
	meta:
		description = "Petite 1.3a"
	strings:
		$0 = {B8 00 00 00 00 66 9C 60 50 8D 88 00 00 00 00 8D 90 00 00 00 00 8B DC 8B E1 68 00 00 00 00 53 50 80 04 24 08 50 80 04 24 42 50 80 04 24 61 50 80 04 24 9D 50 80 04 24 BB 83 3A 00 0F 84 DC 14 00 00 8B 44 24 18 F6 42 03 80 74 19 FD 80 72 03 80}
	condition:
		$0 at pe.entry_point
}