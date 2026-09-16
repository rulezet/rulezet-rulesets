rule shellcode_hash__recv : hardened limited
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
		desc = "shellcode.hash  recv"
		mitre = "T1106"

	strings:
		$h_raw = {62 36 31 39 31 38 65 37}
		$h_hex = { b61918e7 }

	condition:
		filesize < 1MB and any of them
}