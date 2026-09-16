rule suspicious_obfuscation_using_util_byteToChar : hardened limited
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
		desc = "suspicious.obfuscation using util.byteToChar"
		mitre = "T1027"

	strings:
		$h_raw1 = {62 79 74 65 54 6f 43 68 61 72}

	condition:
		filesize < 1MB and any of them
}