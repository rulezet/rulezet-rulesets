rule Win_Trojan_Vole_2
{
strings:
	$a0 = { b440b9eb018d960600cd21e80500b43ecd21c38db63300b99901803400464975f9c3 }


condition:
	$a0
}