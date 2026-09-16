rule suspicious_obfuscation_using_substring : hardened
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
		desc = "suspicious.obfuscation using substring"
		mitre = "T1027"

	strings:
		$h_reg1 = /\.substring(\s{0,3}?)\(/

	condition:
		filesize < 1MB and any of them
}