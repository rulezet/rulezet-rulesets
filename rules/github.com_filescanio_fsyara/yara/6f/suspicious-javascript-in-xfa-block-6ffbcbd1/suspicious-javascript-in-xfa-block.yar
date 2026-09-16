rule suspicious_javascript_in_XFA_block : hardened limited
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
		desc = "suspicious.javascript in XFA block"
		mitre = "T1027 T1059.007"

	strings:
		$h_raw1 = {61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 6a 61 76 61 73 63 72 69 70 74}
		$h_raw2 = {61 70 70 6c 69 63 61 74 69 6f 6e 23 32 46 78 2d 6a 61 76 61 73 63 72 69 70 74}

	condition:
		any of them
}