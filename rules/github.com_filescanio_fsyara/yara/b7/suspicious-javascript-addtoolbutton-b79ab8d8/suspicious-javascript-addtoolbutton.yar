rule suspicious_javascript_addToolButton : hardened limited
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
		desc = "suspicious.javascript addToolButton"
		mitre = "T1059.007"

	strings:
		$h_raw1 = {61 70 70 2e 61 64 64 54 6f 6f 6c 42 75 74 74 6f 6e}

	condition:
		any of them
}