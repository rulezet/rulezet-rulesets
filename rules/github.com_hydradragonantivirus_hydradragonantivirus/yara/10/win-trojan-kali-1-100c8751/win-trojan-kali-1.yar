rule Win_Trojan_Kali_1
{
strings:
	$a0 = { 2d030089847002b904008d946f02b440cd21b800428b94bc028b8cba0283e1e080c91d050115cd21 }


condition:
	$a0
}