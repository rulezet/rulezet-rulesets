rule Win_Trojan_Small_4415
{
strings:
	$a0 = { 56e9690000006a006a008d7f006a00ff }


condition:
	$a0
}