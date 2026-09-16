rule Win_Trojan_Peed_227
{
strings:
	$a0 = { 558bec83ec4c535657[0-15]ff15042040008945d8 }


condition:
	$a0
}