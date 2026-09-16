rule Win_Trojan_SomeKit_12
{
strings:
	$a0 = { 40b904008d96be00cd21fe86c200b802422bc999cd21b440b921018d960600cd21b43ecd21c3 }


condition:
	$a0
}