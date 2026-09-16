rule Win_Trojan_VCC_20
{
strings:
	$a0 = { 962501e88ffeb440b9b1018d960501cd21e881feb800422bc999cd21b440b904008d969101cd21 }


condition:
	$a0
}