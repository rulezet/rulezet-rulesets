rule Win_Trojan_F4_1
{
strings:
	$a0 = { e800005e83c616908bfeb96005fcbabf96ac32c202c6aae2f5 }


condition:
	$a0
}