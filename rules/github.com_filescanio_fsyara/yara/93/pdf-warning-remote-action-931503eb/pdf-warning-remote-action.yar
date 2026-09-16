rule pdf_warning_remote_action : hardened
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 5
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_active"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "pdf.exploit action uri"
		mitre = "T1566.002"

	strings:
		$h_reg1 = /\/(A|#41)(c|#63)(t|#74)(i|#69)(o|#6F)(n|6e)\s*\/(U|#55)(R|#52)(I|49)/
		$h_reg2 = /\/(A|#41)(c|#63)(t|#74)(i|#69)(o|#6F)(n|6e)\s*\/(S|#53)\s*\/(U|#55)(R|#52)(I|49)/

	condition:
		any of them
}