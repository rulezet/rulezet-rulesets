rule suspicious_pdf_embedded_PDF_file : hardened limited
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
		desc = "suspicious.pdf embedded PDF file"
		mitre = "T1204.002"

	strings:
		$h_raw1 = {61 70 70 6c 69 63 61 74 69 6f 6e 23 32 46 70 64 66}

	condition:
		any of them
}