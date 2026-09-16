rule suspicious_string__shellcode_ : hardened limited
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
		desc = "suspicious.string -shellcode-"
		mitre = "T1027 T1059.007"

	strings:
		$h_raw1 = {76 61 72 20 73 68 65 6c 6c 63 6f 64 65}

	condition:
		any of them
}