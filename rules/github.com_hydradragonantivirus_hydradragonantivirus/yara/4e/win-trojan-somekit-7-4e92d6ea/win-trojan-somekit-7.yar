rule Win_Trojan_SomeKit_7
{
strings:
	$a0 = { b904008d96a600cd21fe86aa00b802422bc999cd21b440b909018d960600cd21b43ecd21c3 }


condition:
	$a0
}