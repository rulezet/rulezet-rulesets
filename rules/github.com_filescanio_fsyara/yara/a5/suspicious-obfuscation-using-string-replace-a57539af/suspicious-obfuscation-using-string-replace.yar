rule suspicious_obfuscation_using_String_replace : hardened limited
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
		desc = "suspicious.obfuscation using String.replace"
		mitre = "T1027"

	strings:
		$h_reg1 = /'re'(.{1,24}?)'place'/
		$h_raw2 = {2e 72 65 70 6c 61 63 65}

	condition:
		filesize < 1MB and any of them
}