rule shellcode_hash__WinExec : hardened limited
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
		desc = "shellcode.hash  WinExec"
		mitre = "T1059.003"

	strings:
		$h_raw = {39 38 66 65 38 61 30 65}
		$h_hex = { 98fe8a0e }

	condition:
		filesize < 1MB and any of them
}