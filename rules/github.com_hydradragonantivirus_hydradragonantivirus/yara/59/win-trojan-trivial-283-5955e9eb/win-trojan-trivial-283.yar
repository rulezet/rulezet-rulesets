rule Win_Trojan_Trivial_283
{
strings:
	$a0 = { b47ab44eba1b0190cd21b4b3b43cba8e00ba9e00e90000cd21b22b2a2e2a00b74087d183f17c83f17c9390 }


condition:
	$a0
}