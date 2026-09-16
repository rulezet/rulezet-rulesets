import "pe"
rule _RPoly_crypt_10b_from_Vaska_18032007__1905_
{
	meta:
		description = "RPoly crypt 1.0b from Vaska (18.03.2007 - 19:05)"
	strings:
		$0 = {83 04 24 05 C3 60}
	condition:
		$0 at pe.entry_point
}