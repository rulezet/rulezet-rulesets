rule Win_Trojan_TV_3
{
strings:
	$a0 = { b904008d96db00cd21fe86df00b802422bc999cd21b440b946018d960600cd21b43ecd21c3 }


condition:
	$a0
}