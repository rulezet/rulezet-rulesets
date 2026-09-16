rule suspicious_obfuscation_jjencoded_javascript : hardened limited
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
		desc = "suspicious.obfuscation jjencoded javascript"
		mitre = "T1059.007"

	strings:
		$h_raw1 = {3a 2b 2b 24 2c 24 24 24 24 3a}
		$h_raw2 = {24 24 3a 2b 2b 24 2c 24 24 24}

	condition:
		any of them
}