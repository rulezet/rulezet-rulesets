rule suspicious_embedded_external_content : hardened limited
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
		desc = "suspicious.embedded external content"
		mitre = "T1566.002"

	strings:
		$h_raw1 = {2f 53 20 2f 55 52 49}

	condition:
		any of them
}