import "pe"
rule _DOS_Extender_by_Doug_Hoffmann_1994_
{
	meta:
		description = "DOS Extender by Doug Hoffmann 1994"
	strings:
		$0 = {16 53 66 5B 72 EC 3B C8 75 E8 36 66 89 36 D2 01 57 36 8B 3E 00 00 8B 0E 06 00 8B 36 18 00 66 C1 CB 10 66 0F B7 C3 8B D0 AD 8B 1C 3B DF 0F 8D 08 00 03 DA 8E C3 26 67 01 10 83 C6 02 E2 EA B4 0F CD 10 2E A2 00 00 5F 16 1F 66 8F 06 D6 01 66 8F}
	condition:
		$0 at pe.entry_point
}