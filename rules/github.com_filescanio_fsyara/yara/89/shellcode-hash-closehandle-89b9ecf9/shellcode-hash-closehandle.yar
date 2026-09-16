rule shellcode_hash__CloseHandle : hardened limited
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
		desc = "shellcode.hash  CloseHandle"
		mitre = "T1106"

	strings:
		$h_raw = {66 62 39 37 66 64 30 66}
		$h_hex = { fb97fd0f }

	condition:
		filesize < 1MB and any of them
}