rule suspicious_string_heap_spray_shellcode : hardened limited
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
		desc = "suspicious.string heap spray shellcode"
		mitre = "T1027"

	strings:
		$h_raw1 = {22 25 22 20 2b 20 22 75 22 20 2b 20 22 30 22 20 2b 20 22 63 22 20 2b 20 22 30 22 20 2b 20 22 63 22 20 2b 20 22 25 75 22 20 2b 20 22 30 22 20 2b 20 22 63 22 20 2b 20 22 30 22 20 2b 20 22 63 22}

	condition:
		any of them
}