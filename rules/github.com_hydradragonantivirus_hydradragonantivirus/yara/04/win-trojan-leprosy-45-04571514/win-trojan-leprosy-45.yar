rule Win_Trojan_Leprosy_45
{
strings:
	$a0 = { 0e0b0251e80f005bb93b02ba0001b440cd21e80100c3bb }


condition:
	$a0
}