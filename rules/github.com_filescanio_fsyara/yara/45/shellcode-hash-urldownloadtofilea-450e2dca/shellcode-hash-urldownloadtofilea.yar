rule shellcode_hash__URLDownloadToFileA : hardened limited
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
		desc = "shellcode.hash  URLDownloadToFileA"
		mitre = "T1106"

	strings:
		$h_raw = {33 36 31 61 32 66 37 30}
		$h_hex = { 361a2f70 }

	condition:
		filesize < 1MB and any of them
}