rule Win_Trojan_Burger_16
{
strings:
	$a0 = { 3fb9300290ba00e090cd21b43ecd21 }


condition:
	$a0
}