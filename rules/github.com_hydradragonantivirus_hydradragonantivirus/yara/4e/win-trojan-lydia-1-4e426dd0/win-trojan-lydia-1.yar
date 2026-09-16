rule Win_Trojan_Lydia_1
{
strings:
	$a0 = { a68b4475241f3c1f74ef817c79cefa77 }


condition:
	$a0
}