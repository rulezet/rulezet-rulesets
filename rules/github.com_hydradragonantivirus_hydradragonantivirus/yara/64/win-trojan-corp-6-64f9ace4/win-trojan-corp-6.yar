rule Win_Trojan_Corp_6
{
strings:
	$a0 = { b440b994028d960600cd21e80500b43ecd21c38db61f00b95602803400464975f9c3 }


condition:
	$a0
}