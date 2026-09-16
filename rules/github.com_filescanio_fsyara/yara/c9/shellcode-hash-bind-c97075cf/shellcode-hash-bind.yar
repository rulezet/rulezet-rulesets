rule shellcode_hash__bind : hardened limited
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
		desc = "shellcode.hash  bind"
		mitre = "T1106"

	strings:
		$h_raw = {61 34 31 61 37 30 63 37}
		$h_hex = { a41a70c7 }

	condition:
		filesize < 1MB and any of them
}