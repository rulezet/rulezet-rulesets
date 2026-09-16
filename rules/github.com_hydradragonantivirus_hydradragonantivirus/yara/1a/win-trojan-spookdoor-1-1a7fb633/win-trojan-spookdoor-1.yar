rule Win_Trojan_Spookdoor_1
{
strings:
	$a0 = { 706f6f6b5c6269616f7368690000ffffffff070000006269616f73686900ffffffff0500000065786563 }


condition:
	$a0
}