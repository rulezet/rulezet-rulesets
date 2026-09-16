rule shellcode_hash__GetProcAddress : hardened limited
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
		desc = "shellcode.hash  GetProcAddress"
		mitre = "T1129"

	strings:
		$h_raw = {61 61 66 63 30 64 37 63}
		$h_hex = { aafc0d7c }

	condition:
		filesize < 1MB and any of them
}