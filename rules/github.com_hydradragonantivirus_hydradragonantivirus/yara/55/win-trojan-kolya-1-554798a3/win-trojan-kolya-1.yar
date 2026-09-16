rule Win_Trojan_Kolya_1
{
strings:
	$a0 = { e83efeb440b90300bafd14cd21b002e82ffefe06db0eb440b9001633d2cd21e84702b43ecd21 }


condition:
	$a0
}