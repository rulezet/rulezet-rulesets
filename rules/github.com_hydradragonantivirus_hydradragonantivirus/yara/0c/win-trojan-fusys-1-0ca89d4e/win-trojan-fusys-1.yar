rule Win_Trojan_Fusys_1
{
strings:
	$a0 = { 6a048d45f8506a036a00a1ccc1040850e81ff4ffff83c41489c085c07d2268bd960408a140a8040850e8c6f3ffff83c4086a03 }

	$a1 = { 786973740a0053504f4f462045 }


condition:
	$a0 and $a1
}