rule Lumma_1 : hardened
{
	meta:
		author = "kevoreilly"
		description = "Lumma config extraction"
		cape_options = "bp0=$decode+5,action0=string:ebp,count=0,bp1=$patch+8,action1=skip,typestring=Lumma Config"
		packed = "0ee580f0127b821f4f1e7c032cf76475df9724a9fade2e153a69849f652045f8"
		original_yara_name = "Lumma"
		ruleset = "Lumma.yar"
		repository = "kevoreilly/CAPEv2"
		source_url = "https://github.com/kevoreilly/CAPEv2/blob/3c6d7d4f232e43db68ca2dd711f5e9d8e9e033cb/analyzer/windows/data/yara/Lumma.yar"
		license = "Other"
		score = 75

	strings:
		$c2 = {8D 44 24 ?? 50 89 4C 24 ?? FF 31 E8 [4] 83 C4 08 B8 FF FF FF FF}
		$decode = {C6 44 05 00 00 83 C4 2C 5E 5F 5B 5D C3}
		$patch = {66 C7 0? 00 00 8B 46 1? C6 00 01 8B}

	condition:
		uint16( 0 ) == 0x5a4d and 2 of them
}