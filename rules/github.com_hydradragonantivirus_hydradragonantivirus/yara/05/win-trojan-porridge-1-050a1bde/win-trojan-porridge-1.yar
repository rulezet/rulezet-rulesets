rule Win_Trojan_Porridge_1
{
strings:
	$a0 = { ff26050158b43d5acd21a32b01507205b8ffffeb0233c0 }


condition:
	$a0
}