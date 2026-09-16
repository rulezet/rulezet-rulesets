rule Win_Trojan_VCC_28
{
strings:
	$a0 = { b440b93b028d960600cd21e80500b43ecd21c38db61f00b9fd01803400464975f9c3 }


condition:
	$a0
}