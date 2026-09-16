rule Win_Trojan_Kali_3
{
strings:
	$a0 = { 030089847f02b904008d947e02b440cd21b800428b94cb028b8cc90283e1e080c91d050115cd21 }


condition:
	$a0
}