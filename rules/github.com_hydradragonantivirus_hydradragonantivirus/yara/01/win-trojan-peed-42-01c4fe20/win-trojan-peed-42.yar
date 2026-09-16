rule Win_Trojan_Peed_42
{
strings:
	$a0 = { 89e78b7f1c83c0024f83e80183ff0075f4bf }


condition:
	$a0
}