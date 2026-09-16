rule Win_Trojan_VCC_19
{
strings:
	$a0 = { b440b998018d960600cd21e80500b43ecd21c38db62000b95901803400464975f9c3 }


condition:
	$a0
}