rule Win_Trojan_Lemming_4
{
strings:
	$a0 = { 01e800005d81ed09012e803253e3044946ebf6 }


condition:
	$a0
}