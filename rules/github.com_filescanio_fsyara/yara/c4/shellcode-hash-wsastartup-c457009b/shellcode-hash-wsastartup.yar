rule shellcode_hash__WSAStartup : hardened limited
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
		desc = "shellcode.hash  WSAStartup"
		mitre = "T1106"

	strings:
		$h_raw = {63 62 65 64 66 63 33 62}
		$h_hex = { cbedfc3b }

	condition:
		filesize < 1MB and any of them
}