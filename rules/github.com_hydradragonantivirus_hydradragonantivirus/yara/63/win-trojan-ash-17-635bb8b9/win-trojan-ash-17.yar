rule Win_Trojan_Ash_17
{
strings:
	$a0 = { 5d81ed0b018d9e2a01538a862201b9a202300743e2 }


condition:
	$a0
}