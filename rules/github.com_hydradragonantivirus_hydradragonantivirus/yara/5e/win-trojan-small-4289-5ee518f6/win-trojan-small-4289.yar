rule Win_Trojan_Small_4289
{
strings:
	$a0 = { 60e9[0-255]8d44242c8b44200083f801[0-255]8d5c24 }


condition:
	$a0
}