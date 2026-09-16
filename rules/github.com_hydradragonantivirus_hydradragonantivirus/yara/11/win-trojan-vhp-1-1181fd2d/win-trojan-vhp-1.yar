rule Win_Trojan_VHP_1
{
strings:
	$a0 = { b43fb903008bd783c200cd217303eb59 }


condition:
	$a0
}