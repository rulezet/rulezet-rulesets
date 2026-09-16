rule Win_Trojan_OldYankee_3
{
strings:
	$a0 = { 8b1483c6028b041e8ed8b8001acd211f }


condition:
	$a0
}