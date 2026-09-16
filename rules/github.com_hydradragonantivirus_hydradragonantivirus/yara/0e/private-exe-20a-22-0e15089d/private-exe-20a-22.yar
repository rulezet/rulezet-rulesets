import "pe"
rule _Private_EXE_20a__22_
{
	meta:
		description = "Private EXE 2.0a - 2.2"
	strings:
		$0 = {53 E8 00 00 00 00 5B 8B C3 2D 00 00 00 00 50 81 EB 06 10 40 00 8B 83 E7 10 40 00 81 38 64 A1 18 00 0F 85 A4 00 00 00 8D 83 23 11 40 00 50 FF 93 EB 10 40 00 0B C0 74 78 90 90 90 90 89 83 1F 11 40 00 8D 83 27 11 40 00 50 FF B3 1F 11 40 00 FF}
	condition:
		$0 at pe.entry_point
}