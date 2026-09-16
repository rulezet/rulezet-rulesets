rule Win_Trojan_Anto_2
{
strings:
	$a0 = { baf200b8023dcd218bd87234b43f }


condition:
	$a0
}