rule Win_Trojan_Zol_1
{
strings:
	$a0 = { 10907a6f6c2a2e636f6d00eb5990e961000e1fbb00018a2780fc7a751a8a670180fc6f75128a670280fc6c75e983eb }


condition:
	$a0
}