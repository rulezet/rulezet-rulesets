import "pe"
rule _DalKrypt_10__by_DalKiT_
{
	meta:
		description = "DalKrypt 1.0 - by DalKiT"
	strings:
		$0 = {68 00 10 40 00 58 68 ?? ?? ?? 00 5F 33 DB EB 0D 8A 14 03 80 EA 07 80 F2 04 88 14 03 43 81 FB ?? ?? ?? 00 72 EB FF E7}
	condition:
		$0 at pe.entry_point
}