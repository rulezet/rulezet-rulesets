rule Win_Trojan_Small_4064
{
strings:
	$a0 = { e9930000005b5d5f50c359535557e83f000000e985000000 }


condition:
	$a0
}