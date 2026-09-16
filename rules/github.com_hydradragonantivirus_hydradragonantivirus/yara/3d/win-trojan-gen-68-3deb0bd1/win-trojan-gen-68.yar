rule Win_Trojan_Gen_68
{
strings:
	$a0 = { 030101c6b904008cc88ec08ed88f }


condition:
	$a0
}