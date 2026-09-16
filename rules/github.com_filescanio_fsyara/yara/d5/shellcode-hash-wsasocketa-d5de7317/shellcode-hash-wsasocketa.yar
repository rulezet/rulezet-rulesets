rule shellcode_hash__WSASocketA : hardened limited
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
		desc = "shellcode.hash  WSASocketA"
		mitre = "T1106"

	strings:
		$h_raw = {64 39 30 39 66 35 61 64}
		$h_hex = { d909f5ad }

	condition:
		filesize < 1MB and any of them
}