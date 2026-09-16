import "pe"
rule _Vprotect_V17X187__CoooLie_
{
	meta:
		description = "Vprotect V1.7.X-1.8.7 -> CoooLie"
	strings:
		$0 = {58 89 03 8B 07 8B 5F 0C 8B 4F 04 8B 57 08 8B 6F 14 8B 77 18 FF 77 24 9D 8B 67 10 C7 47 50 00 00 00 00 8B 7F 1C C3}
	condition:
		$0 at pe.entry_point
}