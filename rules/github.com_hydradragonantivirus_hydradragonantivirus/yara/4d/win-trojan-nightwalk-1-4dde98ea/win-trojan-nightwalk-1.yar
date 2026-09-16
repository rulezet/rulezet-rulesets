rule Win_Trojan_NightWalk_1
{
strings:
	$a0 = { b640b903008d8603029280a6b1017fcda1c686b101a1ba024233c933c092cd21b640b93501 }


condition:
	$a0
}