rule Win_Trojan_Leprosy_4
{
strings:
	$a0 = { cd21eb00c3558bec8b5604b9ff00 }


condition:
	$a0
}