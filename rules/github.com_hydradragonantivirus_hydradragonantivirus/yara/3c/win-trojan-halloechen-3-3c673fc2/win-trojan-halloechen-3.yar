rule Win_Trojan_Halloechen_3
{
strings:
	$a0 = { 8cd08bd4bc0200368b0e0000e800005b }


condition:
	$a0
}