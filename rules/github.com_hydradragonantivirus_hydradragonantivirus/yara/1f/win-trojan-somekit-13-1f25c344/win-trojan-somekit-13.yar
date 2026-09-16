rule Win_Trojan_SomeKit_13
{
strings:
	$a0 = { b904008d96c400cd21fe86c800b802422bc999cd21b440b927018d960600cd21b43ecd21c3 }


condition:
	$a0
}