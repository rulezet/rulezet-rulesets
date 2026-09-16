import "pe"
rule _CryptC_by_unknown_
{
	meta:
		description = "CryptC [by unknown"
	strings:
		$0 = {FD 53 56 5B 0F A1 BE 00 00 AD 64 8B 16 05 00 64 31 06 05 00 64 89 16 0D 00 AD FF 36 33 01 64 33 06 05 00 C7 07 EB 17 64 33 06 0D 00 8F 06 33 01 31 04 E9 CB FF}
	condition:
		$0 at pe.entry_point
}