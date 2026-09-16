import "pe"
rule _BJFNT_12_
{
	meta:
		description = "BJFNT 1.2"
	strings:
		$0 = {EB 02 69 B1 83 EC 04 EB 03 CD 20 EB EB 01 EB 9C EB 01 EB EB 02 CD 20 60 EB 03 3A 4D 3A E8 03 00 00 00 E9 EB 04 58 40 50 C3 EB 03 CD 20 17 EB 02 CD 20 EB 03 CD 20 EB EB 01 EB FC EB 01 EB EB 02 CD 20 E8 00 00 00 00 EB 03 CD 20 17 5E EB 02 C7}
	condition:
		$0 at pe.entry_point
}