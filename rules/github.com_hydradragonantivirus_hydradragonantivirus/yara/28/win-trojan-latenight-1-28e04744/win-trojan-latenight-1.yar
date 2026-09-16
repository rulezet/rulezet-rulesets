rule Win_Trojan_Latenight_1
{
strings:
	$a0 = { 40b9f8008d940001cd21b8004231c931d2cd21582d03008984b901b440b904008d94b801cd21 }


condition:
	$a0
}