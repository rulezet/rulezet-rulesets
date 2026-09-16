rule suspicious_embedded_OLE_document_header : hardened
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
		desc = "suspicious.embedded OLE document header"
		mitre = "T1204.002"

	strings:
		$h_reg1 = { d0 cf 11 e0}

	condition:
		$h_reg1 at 0
}