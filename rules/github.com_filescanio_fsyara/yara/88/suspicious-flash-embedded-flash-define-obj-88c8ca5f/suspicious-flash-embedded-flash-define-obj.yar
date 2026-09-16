rule suspicious_flash_Embedded_Flash_define_obj : hardened limited
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
		desc = "suspicious.flash Embedded Flash define obj"
		mitre = "T1204.002"

	strings:
		$h_raw1 = {61 70 70 6c 69 63 61 74 69 6f 6e 23 32 46 78 2d 73 68 6f 63 6b 77 61 76 65 2d 66 6c 61 73 68}
		$h_raw2 = {61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 73 68 6f 63 6b 77 61 76 65 2d 66 6c 61 73 68}

	condition:
		any of them
}