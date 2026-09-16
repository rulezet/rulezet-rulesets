rule suspicious_obfuscation_using_unescape : hardened limited
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
		desc = "suspicious.obfuscation using unescape"
		mitre = "T1027"

	strings:
		$h_reg1 = /une(.{0,6}?)sca(.{0,6}?)pe([^\)]{0,6}?)\(/
		$h_reg2 = /un(.{0,6}?)esc(.{0,6}?)ape([^\)]{0,6}?)\(/
		$h_reg3 = /unesc([\W]{0,6}?)ape/
		$h_reg5 = /unescape([^\)]{0,6}?)\(/
		$h_raw6 = {22 75 22 2c 22 73 22 2c 22 70 22 2c 22 63 22 2c 22 6e 22 2c 22 65 22 2c 22 61 22 2c}
		$h_raw7 = {22 73 22 2c 22 6e 22 2c 22 61 22 2c 22 65 22 2c 22 63 22 2c 22 75 22 2c 22 65 22 2c 22 70 22}

	condition:
		any of them
}