rule shellcode_hash__closesocket : hardened limited
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
		desc = "shellcode.hash  closesocket"
		mitre = "T1106"

	strings:
		$h_raw = {65 37 37 39 63 36 37 39}
		$h_hex = { e779c679 }

	condition:
		filesize < 1MB and any of them
}