rule pdf_suspicious_util_printd_used_to_fill_buffers : hardened limited
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
		desc = "pdf.suspicious util.printd used to fill buffers"
		mitre = "T1027 T1059.007"

	strings:
		$h_raw1 = {75 74 69 6c 2e 70 72 69 6e 74 64}

	condition:
		any of them
}