import "pe"
rule _yodas_Crypter_13Ashkbiz_Danehkar_
{
	meta:
		description = "yoda's Crypter 1.3-->Ashkbiz Danehkar"
	strings:
		$0 = {55 8B EC 53 56 57 60 E8 00 00 00 00 5D 81 ED 6C 28 40 00 B9 5D 34 40 00}
	condition:
		$0 at pe.entry_point
}