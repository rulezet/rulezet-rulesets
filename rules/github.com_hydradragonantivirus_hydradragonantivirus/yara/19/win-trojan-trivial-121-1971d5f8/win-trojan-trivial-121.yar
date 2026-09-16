rule Win_Trojan_Trivial_121
{
strings:
	$a0 = { b44eba1801cd21b43cba9e00cd21b74093ba0001b11ccd21 }


condition:
	$a0
}