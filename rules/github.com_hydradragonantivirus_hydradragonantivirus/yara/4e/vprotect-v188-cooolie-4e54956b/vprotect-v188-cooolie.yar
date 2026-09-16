import "pe"
rule _Vprotect_V188__CoooLie_
{
	meta:
		description = "Vprotect V1.8.8 -> CoooLie"
	strings:
		$0 = {FF E0 60 A5 8B 5F 10 83 6F 10 04 83 EB 04 58 89 03 8B 07 8B 5F 0C 8B 4F 04 8B 57 08 8B 6F 14 8B 77 18 FF 77 24 9D 8B 67 10 C7 47 50 00 00 00 00 8B 7F 1C}
	condition:
		$0 at pe.entry_point
}