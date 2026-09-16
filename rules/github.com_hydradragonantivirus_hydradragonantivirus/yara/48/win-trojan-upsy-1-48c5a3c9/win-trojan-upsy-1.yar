rule Win_Trojan_Upsy_1
{
strings:
	$a0 = { b90100ba7cffcd21b440b90100ba8cff832efcff03cd21b440b90200bafcffcd215bb457b001 }


condition:
	$a0
}