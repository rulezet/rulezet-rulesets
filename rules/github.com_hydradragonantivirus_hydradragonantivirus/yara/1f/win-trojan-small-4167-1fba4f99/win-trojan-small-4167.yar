rule Win_Trojan_Small_4167
{
strings:
	$a0 = { 360fbdef8d1de908abc20fad }


condition:
	$a0
}