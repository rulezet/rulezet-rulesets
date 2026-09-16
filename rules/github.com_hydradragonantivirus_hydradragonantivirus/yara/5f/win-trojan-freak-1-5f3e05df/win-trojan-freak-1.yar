rule Win_Trojan_Freak_1
{
strings:
	$a0 = { 49bae6ff8bd8b80242cd21ba4102b90200b43fcd21b4 }


condition:
	$a0
}