rule Win_Trojan_Gigi_1
{
strings:
	$a0 = { b243ac32c2aae2fabe0001b9270033d2ac32e403d08ad8f6e303d0e2f381faae051f8cd88e }


condition:
	$a0
}