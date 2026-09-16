rule shellcode_hash__CreateFileA : hardened limited
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
		desc = "shellcode.hash  CreateFileA"
		mitre = "T1106"

	strings:
		$h_raw = {61 35 31 37 30 30 37 63}
		$h_hex = { a517007c }

	condition:
		filesize < 1MB and any of them
}