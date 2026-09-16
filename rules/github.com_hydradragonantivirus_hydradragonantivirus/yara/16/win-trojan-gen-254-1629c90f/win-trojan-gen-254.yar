rule Win_Trojan_Gen_254
{
strings:
	$a0 = { 9a0000f5009a00006c005589e5b802029a7c02f50081ec0202c6060a26008dbe00ff165731c0509ae40cf500bffa021e }


condition:
	$a0
}