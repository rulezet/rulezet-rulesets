rule suspicious_obfuscation_getAnnots_access_blocks : hardened limited
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
		desc = "suspicious.obfuscation getAnnots access blocks"
		mitre = "T1059.007"

	strings:
		$h_hex1 = {67 [0-2] 65 [0-2] 74 [0-2] 41 [0-2] 6E [0-2] 6E [0-2] 6F [0-2] 74}
		$h_str2 = {((67 65 74 41 6e 6e 6f 74 73) | (67 00 65 00 74 00 41 00 6e 00 6e 00 6f 00 74 00 73 00))}

	condition:
		any of them
}