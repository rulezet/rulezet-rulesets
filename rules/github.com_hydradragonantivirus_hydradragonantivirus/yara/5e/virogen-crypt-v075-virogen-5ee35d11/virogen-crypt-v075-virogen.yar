import "pe"
rule _Virogen_Crypt_v075__Virogen_
{
	meta:
		description = "Virogen Crypt v0.75 -> Virogen"
	strings:
		$0 = {9C 55 E8 EC 00 00 00 87 D5 5D 60 87 D5 80 BD 15 27 40 00 01}
	condition:
		$0 at pe.entry_point
}