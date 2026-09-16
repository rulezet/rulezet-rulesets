rule suspicious_obfuscation_using_substr : hardened limited
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
		desc = "suspicious.obfuscation using substr"
		mitre = "T1027"

	strings:
		$h_raw1 = {73 75 62 73 74 72 28}

	condition:
		filesize < 1MB and any of them
}