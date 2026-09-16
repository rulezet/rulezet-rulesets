rule Win_Trojan_Leprosy_29
{
strings:
	$a0 = { 1e200253e80f005bb99802ba0001b440cd21e80100c3bb }


condition:
	$a0
}