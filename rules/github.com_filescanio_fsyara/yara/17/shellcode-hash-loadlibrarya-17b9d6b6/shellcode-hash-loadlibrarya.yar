rule shellcode_hash__LoadLibraryA : hardened limited
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
		desc = "shellcode.hash  LoadLibraryA"
		mitre = "T1129"

	strings:
		$h_raw = {38 65 34 65 30 65 65 63}
		$h_hex = { 8e4e0eec }

	condition:
		filesize < 1MB and any of them
}