rule Win_Trojan_Tiny_86
{
strings:
	$a0 = { 8cc880c4108ec08bfeff063d01b97f00 }


condition:
	$a0
}