rule Win_Trojan_Buddy_1
{
strings:
	$a0 = { ba8000b80103b9ffffcd13cd20 }


condition:
	$a0
}