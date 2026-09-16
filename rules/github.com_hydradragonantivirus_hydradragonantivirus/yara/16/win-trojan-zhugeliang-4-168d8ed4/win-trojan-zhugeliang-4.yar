rule Win_Trojan_Zhugeliang_4
{
strings:
	$a0 = { 8bec8b76fa83ee03b90110686201fcf3a4c3be0001b80f4bcd218c5c198c5c1d8c5c2133db }


condition:
	$a0
}