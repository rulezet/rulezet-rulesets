rule suspicious_flash_obfuscated_name : hardened limited
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
		desc = "suspicious.flash obfuscated name"
		mitre = "T1027"

	strings:
		$h_raw1 = {2f 52 23 36 39 63 68 4d 23 36 35 23 36 34 69 61 23 35 33 65 23 37 34 74 69 23 36 65 23 36 37 23 37 33 2f}

	condition:
		any of them
}