rule Win_Trojan_Peed_357
{
strings:
	$a0 = { 81fbf0fa00007f03c21000e83300000052ad05 }


condition:
	$a0
}