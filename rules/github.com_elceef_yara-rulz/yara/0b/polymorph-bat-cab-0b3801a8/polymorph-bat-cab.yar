rule Polymorph_BAT_CAB
{
	meta:
		description = "Detects polymorphic BAT/CAB files self-extracting payload with extrac32.exe/extract.exe"
		author = "marcin@ulikowski.pl"
		date = "2024-04-10"
		hash1 = "f1296b12925108a5d675a8b9c2033c0b749b121ae3b5a6a912ce4418daa06d99"

	strings:
		$extract = { 65 78 74 72 61 63 ( 33 32 | 74 ) 20 2f 79 20 22 25 7e 66 30 22 }

	condition:
		uint32be(0) == 0x4d534346 and 		uint32(16) > 80 and 		$extract in (48..80)
}