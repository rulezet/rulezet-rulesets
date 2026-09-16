rule Win_Trojan_Small_5370
{
strings:
	$a0 = { e83d000000e8890000008d2d9f802700 }


condition:
	$a0
}