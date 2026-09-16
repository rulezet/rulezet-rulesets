rule suspicious_obfuscation_using_app_setTimeOut_to_eval_code : hardened limited
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
		desc = "suspicious.obfuscation using app.setTimeOut to eval code"
		mitre = "T1059.007"

	strings:
		$h_raw1 = {61 70 70 2e 73 65 74 54 69 6d 65 4f 75 74}

	condition:
		any of them
}