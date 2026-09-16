rule Win_Trojan_MSTU_5
{
strings:
	$a0 = { 160026bb073deb55c35e8bc6b104d3e80564000e5b03c3 }


condition:
	$a0
}