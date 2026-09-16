import "pe"
rule _Special_EXE_Pasword_Protector_V101__Pavol_Cerven_
{
	meta:
		description = "Special EXE Pasword Protector V1.01 -> Pavol Cerven"
	strings:
		$0 = {60 E8 00 00 00 00 5D 81 ED 06 00 00 00 89 AD 8C 01 00 00 8B C5 2B 85 FE 75 00 00 89 85 3E}
	condition:
		$0 at pe.entry_point
}