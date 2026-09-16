rule Win_Trojan_VCC_26
{
strings:
	$a0 = { 40b904008d96ab01cd21fe86af01b802422bc999cd21b440b916028d960600cd21b43ecd21c3 }


condition:
	$a0
}