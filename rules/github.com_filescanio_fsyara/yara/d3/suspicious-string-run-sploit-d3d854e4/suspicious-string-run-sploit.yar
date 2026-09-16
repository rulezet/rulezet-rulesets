rule suspicious_string__Run_Sploit_ : hardened limited
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
		desc = "suspicious.string -Run_Sploit-"
		mitre = "T1027"

	strings:
		$h_raw1 = {52 75 6e 5f 53 70 6c 6f 69 74}

	condition:
		filesize < 1MB and any of them
}