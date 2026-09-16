rule suspicious_string__HeapSpray_ : hardened limited
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
		desc = "suspicious.string -HeapSpray-"
		mitre = "T1027"

	strings:
		$h_raw1 = {48 65 61 70 53 70 72 61 79}

	condition:
		filesize < 1MB and any of them
}