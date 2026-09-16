rule Win_Trojan_June16th_1
{
strings:
	$a0 = { 33d2e85bffe81200b440ba0001 }


condition:
	$a0
}