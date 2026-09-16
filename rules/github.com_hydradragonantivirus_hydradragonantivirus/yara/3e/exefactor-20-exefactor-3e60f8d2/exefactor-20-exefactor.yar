import "pe"
rule _ExeFactor_20__ExeFactor_
{
	meta:
		description = "ExeFactor 2.0 -> ExeFactor"
	strings:
		$0 = {55 8B EC 81 EC 7C 0B 00 00 53 56 57 E9 00 8B 01 00 55 53 43 41 54 49 4F 4E 33 82 42 9F 51 87 D5 12 BE 0A E2 A9 1B D3 67 F6 81 4F 2C FB 97 2C 96 22 8C EF 0E 7B B8 BE}
	condition:
		$0 at pe.entry_point
}