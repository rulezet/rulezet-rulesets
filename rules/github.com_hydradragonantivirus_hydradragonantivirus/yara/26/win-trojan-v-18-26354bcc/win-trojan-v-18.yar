rule Win_Trojan_V_18
{
strings:
	$a0 = { 01b800008bd8ac30c700c380d700e2f681fbbd08 }


condition:
	$a0
}