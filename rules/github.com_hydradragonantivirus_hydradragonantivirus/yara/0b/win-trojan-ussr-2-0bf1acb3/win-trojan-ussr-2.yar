rule Win_Trojan_USSR_2
{
strings:
	$a0 = { 108cda83c2102e03162000522eff36 }


condition:
	$a0
}