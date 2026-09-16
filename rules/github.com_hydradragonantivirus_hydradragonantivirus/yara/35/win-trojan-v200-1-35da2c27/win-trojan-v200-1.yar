rule Win_Trojan_V200_1
{
strings:
	$a0 = { 2425bad000cd21b419cd2150b40eb2 }


condition:
	$a0
}