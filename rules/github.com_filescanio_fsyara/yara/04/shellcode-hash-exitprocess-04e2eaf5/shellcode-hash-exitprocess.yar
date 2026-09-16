rule shellcode_hash__ExitProcess : hardened limited
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
		desc = "shellcode.hash  ExitProcess"
		mitre = "T1106"

	strings:
		$h_raw = {37 65 64 38 65 32 37 33}
		$h_hex = { 7ed8e273 }

	condition:
		filesize < 1MB and any of them
}