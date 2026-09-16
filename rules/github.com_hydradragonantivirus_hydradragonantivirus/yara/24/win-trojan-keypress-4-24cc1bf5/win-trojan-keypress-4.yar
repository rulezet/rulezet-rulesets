rule Win_Trojan_KeyPress_4
{
strings:
	$a0 = { 05c7073901f9f51fc3f6060c0701740d8cc00510000106 }


condition:
	$a0
}