rule Win_Trojan_Sality_1019
{
strings:
	$a0 = { 558bec51ff15301000108945fc837d0800740e6a028b450850e802ffffff83c4088be55dc3 }


condition:
	$a0
}