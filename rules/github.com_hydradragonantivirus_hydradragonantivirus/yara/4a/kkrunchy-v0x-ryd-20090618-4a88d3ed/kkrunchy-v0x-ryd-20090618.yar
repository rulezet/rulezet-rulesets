import "pe"
rule _kkrunchy_V0X__Ryd__20090618_
{
	meta:
		description = "kkrunchy V0.X -> Ryd * 20090618"
	strings:
		$0 = {89 FE 29 C6 F3 A4 5E EB ?? 00 D2 75 05 8A 16 46 10 D2 C3 31 C9 41 E8 EE FF FF FF 11 C9 E8 E7 FF FF FF 72 F2 C3 31 C0 31 DB 31 C9 5E 89 F7 B9 ?? ?? ?? ?? 8A 07 47 2C E8 3C 01 77 F7 80 ?? ?? 75 F2 8B 07 8A 5F 04 66 C1 E8 08 C1 C0 10 86 C4 29 F8 80 EB E8 01 F0 89 07 83 C7 05 89 D8 E2 D9 8D BE ?? ?? ?? ?? 8B 07 09 C0 74 45 8B 5F 04 8D 84 ?? ?? ?? ?? ?? 01 F3 50 83 C7 08 FF 96 ?? ?? ?? ?? 95 8A 07 47 08 C0 74 DC 89 F9 79 07 0F B7 07 47 50 47 B9 57 48 F2 AE 55 FF 96 ?? ?? ?? ?? 09 C0 74 07 89 03 83 C3 04 EB D8 FF 96 ?? ?? ?? ?? 61 E9}
	condition:
		$0 at pe.entry_point
}