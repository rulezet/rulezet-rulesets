rule Win_Trojan_VCC_34
{
strings:
	$a0 = { 1f03b440b926028d960001cd21b800422bc999cd21b440b904008d961e03cd218086bf0201b4 }


condition:
	$a0
}