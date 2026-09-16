rule suspicious_obfuscation_info_Trailer_to_access_blocks : hardened
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
		desc = "suspicious.obfuscation info.Trailer to access blocks"
		mitre = "T1059.007"

	strings:
		$h_reg1 = /info([\W]{0,4}?)\.([\W]{0,4}?)Trailer/

	condition:
		any of them
}