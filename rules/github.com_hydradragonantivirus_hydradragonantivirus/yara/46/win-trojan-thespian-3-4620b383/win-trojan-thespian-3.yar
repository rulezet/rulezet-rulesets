rule Win_Trojan_Thespian_3
{
strings:
	$a0 = { b440b993018d960600cd21e80500b43ecd21c38db61100b96301803400464975f9c3 }


condition:
	$a0
}