rule Win_Trojan_VCC_15
{
strings:
	$a0 = { b440b97b018d960600cd21e80500b43ecd21c38db61100b94b01803400464975f9c3 }


condition:
	$a0
}