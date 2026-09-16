rule Win_Trojan_Peed_198
{
strings:
	$a0 = { 558bec83ec305356572bdf23cb4a8d0c24f7d04f }


condition:
	$a0
}