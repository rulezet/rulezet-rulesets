rule shellcode_hash__socket : hardened limited
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
		desc = "shellcode.hash  socket"
		mitre = "T1106"

	strings:
		$h_raw = {36 65 30 62 32 66 34 39}
		$h_hex = { 6e0b2f49 }

	condition:
		filesize < 1MB and any of them
}