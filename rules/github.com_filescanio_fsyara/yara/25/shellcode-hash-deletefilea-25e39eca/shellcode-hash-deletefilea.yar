rule shellcode_hash__DeleteFileA : hardened limited
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
		desc = "shellcode.hash  DeleteFileA"
		mitre = "T1106"

	strings:
		$h_raw = {32 35 62 30 66 66 63 32}
		$h_hex = { 25b0ffc2 }

	condition:
		filesize < 1MB and any of them
}