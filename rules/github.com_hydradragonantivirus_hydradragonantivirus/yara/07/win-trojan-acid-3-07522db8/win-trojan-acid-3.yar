rule Win_Trojan_Acid_3
{
strings:
	$a0 = { 03a3c803c706cc03c58aba0001b9b602b44050cd21e82effb90002f7f185d2740140 }


condition:
	$a0
}