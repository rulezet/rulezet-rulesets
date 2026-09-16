import "pe"
rule _Borland_Cpp_TREXE_
{
	meta:
		description = "Borland C++ (TR.EXE)"
	strings:
		$0 = {B4 0F CD 10 3C 03 74 05 B8 03 00 CD 10 BA 00 00 2E 89 16 00 01 8B 2E 02 00 8B 1E 2C 00 8E DA 8C 06 00 00 89 1E 00 00 89 2E 00 00 A1 00 00 8E C0 33 C0 8B D8 8B F8 B9 FF 7F FC F2 AE E3 00 43 26 38 05 75 F6 80 CD 80 F7 D9 89 0E 00 00 B9 00 00}
	condition:
		$0 at pe.entry_point
}