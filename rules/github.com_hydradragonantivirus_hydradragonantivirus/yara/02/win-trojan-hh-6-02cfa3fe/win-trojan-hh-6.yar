rule Win_Trojan_HH_6
{
strings:
	$a0 = { 40b904008d96db01cd21fe86df01b802422bc999cd21b440b946018d960601cd21b43ecd21c3 }


condition:
	$a0
}