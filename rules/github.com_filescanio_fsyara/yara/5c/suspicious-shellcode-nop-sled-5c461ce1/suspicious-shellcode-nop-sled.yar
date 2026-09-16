rule suspicious_shellcode_NOP_Sled : hardened limited
{
	meta:
		is_exploit = false
		is_warning = true
		is_feature = false
		rank = 2
		revision = "1"
		date = "June 07 2020"
		author = "@tylabs"
		sigtype = "pdfexaminer_shellcode"
		copyright = "Copyright 2020 tylabs.com. All rights reserved."
		desc = "suspicious.shellcode NOP Sled"
		mitre = "T1106"

	strings:
		$h_raw = {39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30 39 30}
		$h_hex = { 9090909090909090909090909090909090909090909090909090909090909090909090909090909090909090909090 }

	condition:
		filesize < 1MB and any of them
}