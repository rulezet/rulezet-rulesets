rule shellcode_hash__connect : hardened limited
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
		desc = "shellcode.hash  connect"
		mitre = "T1106"

	strings:
		$h_raw = {65 63 66 39 61 61 36 30}
		$h_hex = { ecf9aa60 }

	condition:
		filesize < 1MB and any of them
}