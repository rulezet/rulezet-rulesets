import "pe"
rule _RPoly_crypt_10b_from_Vaska_18032007__1906_
{
	meta:
		description = "RPoly crypt 1.0b from Vaska (18.03.2007 - 19:06)"
	strings:
		$0 = {E8 00 00 00 00 83}
	condition:
		$0 at pe.entry_point
}