rule Win_Trojan_MegaDestruct_1
{
strings:
	$a0 = { b440b9f7018d960600cd21e80500b43ecd21c38db61f00b9b901803400464975f9c3 }


condition:
	$a0
}