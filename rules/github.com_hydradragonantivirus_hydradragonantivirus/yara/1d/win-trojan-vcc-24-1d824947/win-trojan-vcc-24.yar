rule Win_Trojan_VCC_24
{
strings:
	$a0 = { 5a02b440b961018d960001cd21b800422bc999cd21b440b904008d965902cd218086550201b4 }


condition:
	$a0
}