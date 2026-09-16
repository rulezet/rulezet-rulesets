rule Win_Trojan_Burger_26
{
strings:
	$a0 = { ba0100895606ba00008956558bf583c65ab200b80047 }


condition:
	$a0
}