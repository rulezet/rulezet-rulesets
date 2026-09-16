rule shellcode_hash__send : hardened limited
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
		desc = "shellcode.hash  send"
		mitre = "T1106"

	strings:
		$h_raw = {61 34 31 39 37 30 65 39}
		$h_hex = { a41970e9 }

	condition:
		filesize < 1MB and any of them
}