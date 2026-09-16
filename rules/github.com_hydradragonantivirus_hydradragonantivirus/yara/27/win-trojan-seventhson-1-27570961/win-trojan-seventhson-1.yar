rule Win_Trojan_SeventhSon_1
{
strings:
	$a0 = { 2425cd215ab80133cd210e0e1f07b8000150c3fcb8 }


condition:
	$a0
}