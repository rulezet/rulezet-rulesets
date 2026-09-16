rule Win_Trojan_Dikshev_1
{
strings:
	$a0 = { abbf6101abbf6701ab59b44dfec4cd217229b8013c2bd2fec4b29ffec04acd2193b4412bd2 }


condition:
	$a0
}