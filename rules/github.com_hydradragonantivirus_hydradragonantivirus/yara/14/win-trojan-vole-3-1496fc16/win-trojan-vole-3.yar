rule Win_Trojan_Vole_3
{
strings:
	$a0 = { b440b9ef018d960600cd21e80500b43ecd21c38db63300b99d01803400464975f9c3 }


condition:
	$a0
}