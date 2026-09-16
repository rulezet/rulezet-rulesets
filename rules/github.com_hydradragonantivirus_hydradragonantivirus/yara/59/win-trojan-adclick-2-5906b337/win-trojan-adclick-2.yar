rule Win_Trojan_AdClick_2
{
strings:
	$a0 = { 8216015f00456e637279700774656420627e6f530f6ffe832f554346eb2dfb50db77d8724c61756d }


condition:
	$a0
}