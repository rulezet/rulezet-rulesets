rule shellcode_hash__CreateProcessA : hardened limited
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
		desc = "shellcode.hash  CreateProcessA"
		mitre = "T1106"

	strings:
		$h_raw = {37 32 66 65 62 33 31 36}
		$h_hex = { 72feb316 }

	condition:
		filesize < 1MB and any of them
}