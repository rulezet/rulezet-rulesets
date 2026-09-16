rule shellcode_hash___hwrite : hardened limited
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
		desc = "shellcode.hash  _hwrite"
		mitre = "T1106"

	strings:
		$h_raw = {64 39 38 61 32 33 65 39}
		$h_hex = { d98a23e9 }

	condition:
		filesize < 1MB and any of them
}