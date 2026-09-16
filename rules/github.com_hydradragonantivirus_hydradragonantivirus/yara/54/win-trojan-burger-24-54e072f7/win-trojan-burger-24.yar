rule Win_Trojan_Burger_24
{
strings:
	$a0 = { b43fb9ce0590ba00f890cd21b43ecd21 }


condition:
	$a0
}