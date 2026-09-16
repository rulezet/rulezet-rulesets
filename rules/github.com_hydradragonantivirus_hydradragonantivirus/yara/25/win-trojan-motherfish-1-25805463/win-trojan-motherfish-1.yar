rule Win_Trojan_Motherfish_1
{
strings:
	$a0 = { 59bb61dc01cb0eb9c3101ffec5290f43 }


condition:
	$a0
}