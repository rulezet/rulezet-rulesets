rule suspicious_obfuscation_using_String_fromCharCode : hardened limited
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
		desc = "suspicious.obfuscation using String.fromCharCode"
		mitre = "T1027"

	strings:
		$h_raw1 = {22 72 43 6f 22 2c 22 74 22 2c 22 63 68 61 22 2c 22 22 2c 22 64 65 41 22}
		$h_raw2 = {22 64 65 41 22 2c 22 63 68 61 22 2c 22 72 43 6f 22 2c 22 74 22}
		$h_reg3 = /from([\W]{0,6}?)C([\W]{0,6}?)h([\W]{0,6}?)a(.{0,6}?)r(.{0,6}?)C(.{0,6}?)o([\W]{0,6}?)d([\W]{0,6}?)e/
		$h_raw4 = {2e 66 72 6f 6d 43 68 61 72 43}

	condition:
		any of them
}