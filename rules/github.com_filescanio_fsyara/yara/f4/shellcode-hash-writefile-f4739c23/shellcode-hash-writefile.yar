rule shellcode_hash__WriteFile : hardened limited
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
		desc = "shellcode.hash  WriteFile"
		mitre = "T1059"

	strings:
		$h_raw = {31 66 37 39 30 61 65 38}
		$h_hex = { 1f790ae8 }

	condition:
		filesize < 1MB and any of them
}