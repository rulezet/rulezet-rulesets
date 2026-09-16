rule Win_Trojan_R_89
{
strings:
	$a0 = { ffcd213daaaa741433c08ec0cd12b106d3e02639064a }


condition:
	$a0
}