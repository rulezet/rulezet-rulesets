rule suspicious_obfuscation_toString : hardened limited
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
		desc = "suspicious.obfuscation toString"
		mitre = "T1027"

	strings:
		$h_raw1 = {74 6f 53 74 72 69 6e 67 28}

	condition:
		filesize < 1MB and any of them
}