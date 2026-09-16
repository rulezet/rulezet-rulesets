rule shellcode_hash___lclose : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "shellcode.hash  _lclose"
		mitre = "T1106"

	strings:
		$h_raw = {35 62 34 63 31 61 64 64}
		$h_hex = { 5b4c1add }

	condition:
		filesize < 1MB and any of them
}