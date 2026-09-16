rule Win_Trojan_Nessy_1
{
strings:
	$a0 = { b9f601b440cd81f8b43ecd81f8fa071f5a595e5f5b }


condition:
	$a0
}