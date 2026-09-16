rule Win_Trojan_Zany_7
{
strings:
	$a0 = { 2d030189c5fcbf00018db6bd01a4a4a4b41a8d96cc01cd21b44eb907008d96b701cd2172438d96ea01b43db002cd21 }


condition:
	$a0
}