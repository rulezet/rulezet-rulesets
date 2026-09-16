rule Win_Trojan_Satan_4
{
strings:
	$a0 = { c65e028944018bf58bfe81c6240281c76102b9 }


condition:
	$a0
}