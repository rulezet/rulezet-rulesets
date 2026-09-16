rule Win_Trojan_BFD_2
{
strings:
	$a0 = { b4f0cd1380fc1974108cd8488ed82916 }


condition:
	$a0
}