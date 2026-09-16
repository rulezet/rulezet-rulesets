rule Win_Trojan_Vole_4
{
strings:
	$a0 = { b440b9f3018d960600cd21e80500b43ecd21c38db63300b9a101803400464975f9c3 }


condition:
	$a0
}