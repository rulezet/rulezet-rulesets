rule Win_Trojan_KeyPress_3
{
strings:
	$a0 = { 073401f9f51fc3f606160101740d8cc00510000106 }


condition:
	$a0
}