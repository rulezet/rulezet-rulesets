rule Win_Trojan_Amour_1
{
strings:
	$a0 = { c3b8e848f7d8d0e181c0d85550d0d7d1fb80d29ac3 }


condition:
	$a0
}