rule Win_Trojan_Hero_5
{
strings:
	$a0 = { d2cd21b440b91800bafa03cd21 }


condition:
	$a0
}