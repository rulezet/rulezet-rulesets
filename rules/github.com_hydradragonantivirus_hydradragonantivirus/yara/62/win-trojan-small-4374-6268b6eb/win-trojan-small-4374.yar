rule Win_Trojan_Small_4374
{
strings:
	$a0 = { e8??000000e8??000000[0-255]bb6764b20f81f36764f20f81e889c026262d77c9d8d9 }


condition:
	$a0
}