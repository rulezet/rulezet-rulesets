rule suspicious_embedded_exe_file : hardened
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
		desc = "suspicious.embedded exe file"
		mitre = "T1204.002"

	strings:
		$h_reg1 = /\/Type\/Filespec\/F(.{1,30}?)\.exe/

	condition:
		any of them
}