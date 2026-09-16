rule shellcode_hash__WaitForSingleObject : hardened limited
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
		desc = "shellcode.hash  WaitForSingleObject"
		mitre = "T1106"

	strings:
		$h_raw = {61 64 64 39 30 35 63 65}
		$h_hex = { add905ce }

	condition:
		filesize < 1MB and any of them
}