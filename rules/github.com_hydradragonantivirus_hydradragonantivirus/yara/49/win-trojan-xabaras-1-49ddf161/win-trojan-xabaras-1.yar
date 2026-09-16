rule Win_Trojan_Xabaras_1
{
strings:
	$a0 = { 908a2790909090909090322606019090 }


condition:
	$a0
}