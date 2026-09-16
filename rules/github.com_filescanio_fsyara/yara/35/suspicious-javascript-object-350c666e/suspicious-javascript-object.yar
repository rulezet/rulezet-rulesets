rule suspicious_javascript_object : hardened limited
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
		desc = "suspicious.javascript object"
		mitre = "T1027 T1059.007"

	strings:
		$h_raw1 = {2f 4a 61 76 61 53 63 72 69 70 74}
		$h_raw2 = {2f 4a 53 20}

	condition:
		any of them
}