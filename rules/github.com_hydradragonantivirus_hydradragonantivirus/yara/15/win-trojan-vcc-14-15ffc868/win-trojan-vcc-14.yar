rule Win_Trojan_VCC_14
{
strings:
	$a0 = { b440b96f018d960600cd21e80500b43ecd21c38db61100b93f01803405464975f9c3 }


condition:
	$a0
}