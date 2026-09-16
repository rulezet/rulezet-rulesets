import "pe"
rule _ASL_Crypt_01_
{
	meta:
		description = "ASL Crypt 0.1"
	strings:
		$0 = {41 2E 53 2E 4C F8 43 72 79 70 74}
	condition:
		$0 at pe.entry_point
}