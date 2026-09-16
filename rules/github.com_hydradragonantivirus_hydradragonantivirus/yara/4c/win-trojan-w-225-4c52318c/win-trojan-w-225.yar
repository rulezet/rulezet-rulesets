rule Win_Trojan_W_225
{
strings:
	$a0 = { 9423400024244000540000005000000068 }


condition:
	$a0
}