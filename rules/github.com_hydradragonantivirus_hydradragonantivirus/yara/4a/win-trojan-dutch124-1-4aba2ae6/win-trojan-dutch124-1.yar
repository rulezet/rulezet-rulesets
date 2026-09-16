rule Win_Trojan_Dutch124_1
{
strings:
	$a0 = { b43fcd218bf2803c4d741cb002e8cfff97b97c00b4 }


condition:
	$a0
}