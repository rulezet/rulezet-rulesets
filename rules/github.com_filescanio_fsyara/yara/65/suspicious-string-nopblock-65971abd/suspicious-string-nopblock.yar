rule suspicious_string_nopblock : hardened limited
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
		desc = "suspicious.string nopblock"
		mitre = "T1027"

	strings:
		$h_raw1 = {6e 6f 70 62 6c 6f 63 6b}

	condition:
		filesize < 1MB and any of them
}