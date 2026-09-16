rule Win_Trojan_VCC_23
{
strings:
	$a0 = { b9c1018d960600cd21e80500b43ecd21c38db62000b9 }


condition:
	$a0
}