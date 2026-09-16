rule Win_Trojan_Nephew_1
{
strings:
	$a0 = { 8ec0bef90b0e1fbff004b90600f3a4bb0301b9f40a32e49af004000043e2f8 }


condition:
	$a0
}