rule Win_Trojan_Shatin_1
{
strings:
	$a0 = { e2f52ec60627070190b43cb92020ba15070e1fcd218bd8b440ba0001b9a00fcd21b43ecd21ebfe }


condition:
	$a0
}