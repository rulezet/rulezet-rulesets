rule shellcode_hash__SetUnhandledExceptionFilter : hardened limited
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
		desc = "shellcode.hash  SetUnhandledExceptionFilter"
		mitre = "T1106"

	strings:
		$h_raw = {66 30 38 61 30 34 35 66}
		$h_hex = { f08a045f }

	condition:
		filesize < 1MB and any of them
}