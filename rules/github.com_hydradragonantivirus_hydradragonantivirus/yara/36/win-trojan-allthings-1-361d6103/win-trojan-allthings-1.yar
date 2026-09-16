rule Win_Trojan_AllThings_1
{
strings:
	$a0 = { b440b919028d960600cd21e80500b43ecd21c38db61100b9e901803400464975f9c3 }


condition:
	$a0
}