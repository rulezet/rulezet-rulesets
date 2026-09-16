import "pe"
rule _Stones_PE_Encryptor_v20__Stone_
{
	meta:
		description = "Stone's PE Encryptor v2.0 -> Stone"
	strings:
		$0 = {53 51 52 56 57 55 E8 00 00 00 00 5D 81 ED 42 30 40 ?? FF 95 32 35 40 ?? B8 37 30 40 ?? 03 C5 2B 85 1B 34 40 ?? 89 85 27 34 40 ?? 83}
	condition:
		$0 at pe.entry_point
}