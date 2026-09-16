rule Win_Trojan_Angel_1
{
strings:
	$a0 = { c3538b9f0410cd215bc3b43fe8f2ffc3b440e8ecffc3b4438bd381c21e04cd21c3b42a }


condition:
	$a0
}