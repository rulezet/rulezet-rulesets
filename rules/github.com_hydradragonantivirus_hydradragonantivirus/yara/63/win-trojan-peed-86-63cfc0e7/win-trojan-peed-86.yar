rule Win_Trojan_Peed_86
{
strings:
	$a0 = { 558bec83ec0c535657e805020000e8e3 }


condition:
	$a0
}