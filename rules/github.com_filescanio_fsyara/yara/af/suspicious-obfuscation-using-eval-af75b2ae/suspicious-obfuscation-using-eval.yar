rule suspicious_obfuscation_using_eval : hardened limited
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
		desc = "suspicious.obfuscation using eval"
		mitre = "T1027"

	strings:
		$h_reg1 = /eval(\s{0,3}?)\(/
		$h_raw2 = {65 76 61 6c 5c}
		$h_raw3 = {65 76 61 6c 2c}
		$h_reg4 = /'e'(.{1,30}?)'va'(.{1,3}?)'l/
		$h_raw5 = {22 6c 22 2c 22 76 22 2c 22 65 22 2c 22 61 22}
		$h_raw6 = {22 65 22 2c 22 6c 22 2c 22 61 22 2c 22 76 22}
		$h_reg7 = /=(\s{0,6}?)eval/

	condition:
		any of them
}