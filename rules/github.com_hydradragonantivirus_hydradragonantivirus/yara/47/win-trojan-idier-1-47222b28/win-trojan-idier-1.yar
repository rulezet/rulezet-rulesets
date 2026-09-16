rule Win_Trojan_Idier_1
{
strings:
	$a0 = { 40b904008d961701cd21fe861b01b802422bc999cd21b440b97f018d960600cd21b43ecd21c3 }


condition:
	$a0
}