import "pe"
rule _Werus_Crypter_10__by_Kas_
{
	meta:
		description = "Werus Crypter 1.0 - by Kas"
	strings:
		$0 = {BB E8 12 40 00 80 33 05 E9 7D FF FF FF}
	condition:
		$0 at pe.entry_point
}