import "pe"
rule _Rec_014_
{
	meta:
		description = "Rec 0.14"
	strings:
		$0 = {06 1E 0E 0E 07 1F 52 B8 00 30 1E CD 21 86 E0 3D FF 02 73 02 CD 20 0E 1F B4 09 E8 03 00 24 24 EA 5A CD 21 1F 5A 53 BB EB 04 5B EB FB 9A EB 2D FE 20 E7 E4 9B 20 30 2E 31 34 20 28 87 29 20 EB 98 20 E7 30 24 EE 20 FE 20 9F AD 64 30 3A 20 32 3A}
	condition:
		$0 at pe.entry_point
}