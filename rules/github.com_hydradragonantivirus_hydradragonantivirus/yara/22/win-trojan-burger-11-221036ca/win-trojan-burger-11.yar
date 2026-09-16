rule Win_Trojan_Burger_11
{
strings:
	$a0 = { e3eb0190b43db002ba9e00cd218b }


condition:
	$a0
}