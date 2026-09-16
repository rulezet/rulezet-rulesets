rule Win_Trojan_Small_V_1
{
strings:
	$a0 = { 3dcd218bd8b903008bd5b43fcd21b80242998bcacd21 }


condition:
	$a0
}