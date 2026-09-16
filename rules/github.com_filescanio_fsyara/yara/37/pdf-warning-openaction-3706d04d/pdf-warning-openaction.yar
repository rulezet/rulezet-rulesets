rule pdf_warning_openaction : hardened
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = true
		rank = 1
		revision = "1"
		date = "July 14 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_obfuscation"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.warning OpenAction"
		mitre = "T1203 T1204.002"

	strings:
		$h_reg1 = /\/(O|#4F)(p|#70)(e|#65)(n|#6e)(A|#41)(c|#63)(t|#74)(i|#69)(o|#6F)(n|6e)/

	condition:
		any of them
}