rule Win_Trojan_V1226D_1
{
strings:
	$a0 = { 8bde33d2b8540250335422464648 }


condition:
	$a0
}