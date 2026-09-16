rule Win_Trojan_Packed_64
{
strings:
	$a0 = { 53682b81a2685b5b60524a5ae80000000003f02bf05e }


condition:
	$a0
}