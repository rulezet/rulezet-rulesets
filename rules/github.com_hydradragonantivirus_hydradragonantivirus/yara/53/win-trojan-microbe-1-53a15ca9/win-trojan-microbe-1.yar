rule Win_Trojan_Microbe_1
{
strings:
	$a0 = { 1ed701cd13597308b400cd13e2e2cd18 }


condition:
	$a0
}