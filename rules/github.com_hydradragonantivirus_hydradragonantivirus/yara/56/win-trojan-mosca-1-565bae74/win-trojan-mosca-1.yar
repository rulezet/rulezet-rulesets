rule Win_Trojan_Mosca_1
{
strings:
	$a0 = { bd00008a9e240153b9dc0483c10089c95bbe250101ee2e301c46e2fae90100 }


condition:
	$a0
}