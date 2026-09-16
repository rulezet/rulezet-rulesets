import "pe"
rule _NoodleCrypt_200_Eng__NoodleSpa_
{
	meta:
		description = "NoodleCrypt 2.00 (Eng) -> NoodleSpa"
	strings:
		$0 = {EB 01 9A E8 76 00 00 00 EB 01 9A E8 65 00 00 00 EB 01 9A E8 7D 00 00 00 EB 01 9A E8 55 00 00 00 EB 01 9A E8 43 04 00 00 EB 01 9A E8 E1 00 00 00 EB 01 9A E8 3D 00 00 00 EB 01 9A E8 EB 01 00 00 EB 01 9A E8 2C 04 00 00 EB 01 9A E8 25 00 00 00 EB 01 9A E8 02}
	condition:
		$0 at pe.entry_point
}