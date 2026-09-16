import "pe"
rule _ProtEXE_211_COM_
{
	meta:
		description = "ProtEXE 2.11 [COM]"
	strings:
		$0 = {9C 9C 58 25 FF 0F 50 9D 9C 58 25 00 F0 3D 00 F0 74 2A 9C 58 25 FF 0F 0D 00 70 50 9D 9C 58 25 00 70 74 19 BA 64 00 B0 AD EB 01 88 EE EB 01 A0 0F 20 00 F8 BA 64 00 B0 AE EB 01 88 EE 9D 1E 06 33 C0 8E D8 FF 36 0C 00 FF 36 0E 00 B8 00 00 A3 0C}
	condition:
		$0 at pe.entry_point
}