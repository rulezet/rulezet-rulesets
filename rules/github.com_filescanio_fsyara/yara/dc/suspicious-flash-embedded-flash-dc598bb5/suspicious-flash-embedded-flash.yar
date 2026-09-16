rule suspicious_flash_Embedded_Flash : hardened
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
		desc = "suspicious.flash Embedded Flash"

	strings:
		$h_reg1 = /^FWS/
		$h_reg2 = /^CWS/
		$h_reg3 = /^SWF/
		$h_hex4 = {0D0A43575309A2D20000789CECBD797C54}
		$h_reg5 = /\x0aFWS/
		$h_reg6 = /\x0aCWS/
		$h_reg7 = /\x0aSWF/

	condition:
		any of them
}