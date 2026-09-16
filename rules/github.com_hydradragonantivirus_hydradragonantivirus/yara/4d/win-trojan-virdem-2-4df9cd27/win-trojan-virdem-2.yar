rule Win_Trojan_Virdem_2
{
strings:
	$a0 = { 80008d3ed703b92000f3a4b8000026 }


condition:
	$a0
}