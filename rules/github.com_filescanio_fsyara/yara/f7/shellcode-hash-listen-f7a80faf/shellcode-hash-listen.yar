rule shellcode_hash__listen : hardened limited
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
		desc = "shellcode.hash  listen"
		mitre = "T1106"

	strings:
		$h_raw = {61 34 61 64 32 65 65 39}
		$h_hex = { a4ad2ee9 }

	condition:
		filesize < 1MB and any of them
}