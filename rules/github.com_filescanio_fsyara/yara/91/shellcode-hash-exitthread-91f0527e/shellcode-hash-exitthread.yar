rule shellcode_hash__ExitThread : hardened limited
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
		desc = "shellcode.hash  ExitThread"
		mitre = "T1106"

	strings:
		$h_raw = {65 66 63 65 65 30 36 30}
		$h_hex = { efcee060 }

	condition:
		filesize < 1MB and any of them
}