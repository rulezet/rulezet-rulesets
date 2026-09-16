rule suspicious_flash_writeMultiByte : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 1
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.flash writeMultiByte"
		mitre = "T1027"

	strings:
		$h_raw1 = {77 72 69 74 65 4d 75 6c 74 69 42 79 74 65}

	condition:
		filesize < 1MB and any of them
}