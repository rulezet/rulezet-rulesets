rule Win_Trojan_RussianTiny_1
{
strings:
	$a0 = { 521e80ec4b7547b8023dcd21724093b904000e1f33d2 }


condition:
	$a0
}