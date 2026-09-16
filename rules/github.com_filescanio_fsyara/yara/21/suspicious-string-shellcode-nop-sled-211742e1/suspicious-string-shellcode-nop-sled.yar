rule suspicious_string_Shellcode_NOP_sled : hardened limited
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
		desc = "suspicious.string Shellcode NOP sled"
		mitre = "T1027"

	strings:
		$h_raw1 = {25 75 39 30 39 30}

	condition:
		filesize < 1MB and any of them
}