rule Win_Trojan_Copyright_2
{
strings:
	$a0 = { 75f2e2ea33c0cd16b80006b70733 }


condition:
	$a0
}