rule Win_Trojan_Tiny_58
{
strings:
	$a0 = { 8896dd01eb02eb23b440b9dc008d960001cd21b8004233c999cd21b440b91a008d96dd01cd212e }


condition:
	$a0
}