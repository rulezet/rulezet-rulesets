rule Win_Trojan_Mozart_1
{
strings:
	$a0 = { 40b904008d96ac00cd21fe86b000b802422bc999cd21b440b90f018d960600cd21b43ecd21c3 }


condition:
	$a0
}