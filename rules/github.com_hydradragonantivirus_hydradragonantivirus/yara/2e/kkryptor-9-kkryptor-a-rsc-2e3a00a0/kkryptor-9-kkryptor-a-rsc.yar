import "pe"
rule _kkryptor_9__kkryptor_a__rsc_
{
	meta:
		description = "k.kryptor 9 / k.kryptor a -> r!sc"
	strings:
		$0 = {60 E8 00 00 00 00 5E B9 47 08 00 00 2B C0 02 04 0E D3 C0 49 79 F8 41 8D 7E 2C 33 46 F6 66 B9 1B}
	condition:
		$0 at pe.entry_point
}