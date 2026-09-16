rule Win_Trojan_100_Years_1
{
strings:
	$a0 = { fe3a558bec50817e0400c0730c2ea147 }


condition:
	$a0
}