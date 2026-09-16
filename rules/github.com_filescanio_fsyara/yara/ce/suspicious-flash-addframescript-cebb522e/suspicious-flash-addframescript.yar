rule suspicious_flash_addFrameScript : hardened limited
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
		desc = "suspicious.flash addFrameScript"
		mitre = "T1027"

	strings:
		$h_raw1 = {61 64 64 46 72 61 6d 65 53 63 72 69 70 74}

	condition:
		filesize < 1MB and any of them
}