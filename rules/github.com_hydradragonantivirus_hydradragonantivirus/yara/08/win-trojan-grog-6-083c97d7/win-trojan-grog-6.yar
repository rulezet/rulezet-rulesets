rule Win_Trojan_Grog_6
{
strings:
	$a0 = { 0701bbd7013c00740f473007434702c74781fbb705907e }


condition:
	$a0
}