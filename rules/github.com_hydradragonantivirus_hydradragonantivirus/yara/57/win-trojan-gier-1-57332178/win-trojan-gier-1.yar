rule Win_Trojan_Gier_1
{
strings:
	$a0 = { 020055ed00000200010001030000dc090000020000000103 }


condition:
	$a0
}