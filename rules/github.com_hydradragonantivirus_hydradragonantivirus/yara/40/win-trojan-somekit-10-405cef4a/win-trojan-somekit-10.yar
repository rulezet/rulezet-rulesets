rule Win_Trojan_SomeKit_10
{
strings:
	$a0 = { b904008d96b600cd21fe86ba00b802422bc999cd21b440b919018d960600cd21b43ecd21c3 }


condition:
	$a0
}