rule Win_Trojan_Peed_118
{
strings:
	$a0 = { b870b24000908?0c24 }


condition:
	$a0
}