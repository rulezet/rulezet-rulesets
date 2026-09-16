rule Win_Trojan_Perelett_2
{
strings:
	$a0 = { e8000000005de82d0400006a45598db5 }


condition:
	$a0
}