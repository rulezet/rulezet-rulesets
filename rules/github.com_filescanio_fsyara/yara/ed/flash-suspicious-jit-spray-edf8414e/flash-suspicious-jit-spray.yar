rule flash_suspicious_jit_spray : hardened
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "flash.suspicious jit_spray"
		mitre = "T1027 T1059.007"

	strings:
		$h_hex1 = {076A69745F65676708}

	condition:
		any of them
}