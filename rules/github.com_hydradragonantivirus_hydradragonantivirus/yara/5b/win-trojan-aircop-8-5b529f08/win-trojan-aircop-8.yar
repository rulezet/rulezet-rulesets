rule Win_Trojan_Aircop_8
{
strings:
	$a0 = { 2ec001530ee8b1ff0ebb4c00e8adff5bcd12 }


condition:
	$a0
}