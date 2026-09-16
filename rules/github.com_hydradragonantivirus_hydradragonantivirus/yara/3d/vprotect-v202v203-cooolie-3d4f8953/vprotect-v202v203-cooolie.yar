import "pe"
rule _Vprotect_V202V203__CoooLie_
{
	meta:
		description = "Vprotect V2.0.2-V2.0.3 -> CoooLie"
	strings:
		$0 = {66 F7 D7 66 50 66 58 66 F7 D7 9C 9D 8B 67 28 57 66 8B DB 5F 61 8D AD F4 FF FF FF 8D AD 0C 00 00 00 66 57 66 5F 8B FF 9D 9C 8D 80 F0 FF FF FF 8D 80 10 00 00 00 9D 66 F7 D2 66 F7 D2}
	condition:
		$0 at pe.entry_point
}