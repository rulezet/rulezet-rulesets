import "pe"
rule _PEncrypt_10__JunkCode_
{
	meta:
		description = "PEncrypt 1.0 -> JunkCode"
	strings:
		$0 = {60 9C BE 00 10 40 00 8B FE B9 ?? ?? ?? ?? BB 78 56 34 12 AD 33 C3 AB E2 FA 9D 61 E9 ?? ?? ?? FF}
	condition:
		$0 at pe.entry_point
}