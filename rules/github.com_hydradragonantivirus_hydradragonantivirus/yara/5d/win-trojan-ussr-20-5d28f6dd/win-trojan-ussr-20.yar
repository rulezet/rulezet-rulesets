rule Win_Trojan_USSR_20
{
strings:
	$a0 = { b440cd217215b8004233d28bcacd21 }


condition:
	$a0
}