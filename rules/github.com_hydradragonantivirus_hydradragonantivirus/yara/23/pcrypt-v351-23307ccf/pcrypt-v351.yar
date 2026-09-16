import "pe"
rule _PCrypt_v351_
{
	meta:
		description = "PCrypt v3.51"
	strings:
		$0 = {50 43 52 59 50 54 FF 76 33 2E 35 31 00 E9}
	condition:
		$0 at pe.entry_point
}