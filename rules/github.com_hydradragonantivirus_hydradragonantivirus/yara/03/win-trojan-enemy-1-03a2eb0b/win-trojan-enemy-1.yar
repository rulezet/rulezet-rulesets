rule Win_Trojan_Enemy_1
{
strings:
	$a0 = { 03c58aba0001b98402b44050cd21e82bffb90002f7f185d2740140a38c0389168a03 }


condition:
	$a0
}