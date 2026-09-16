rule shellcode_hash__GetSystemDirectoryA : hardened limited
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
		desc = "shellcode.hash  GetSystemDirectoryA"
		mitre = "T1106"

	strings:
		$h_raw = {63 31 37 39 65 35 62 38}
		$h_hex = { c179e5b8 }

	condition:
		filesize < 1MB and any of them
}