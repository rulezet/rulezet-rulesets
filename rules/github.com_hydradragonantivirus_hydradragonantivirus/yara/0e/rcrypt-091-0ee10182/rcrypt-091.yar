import "pe"
rule _RCrypt_091_
{
	meta:
		description = "R-Crypt 0.91"
	strings:
		$0 = {68 00 01 60 BF 03 01 B9 00 00 B0 00 2E 30 05 FE C0 47 E2 F8 61 C7 06 00 01 00 00 C6 06 02 01 00 C3}
	condition:
		$0 at pe.entry_point
}