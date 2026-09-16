rule Win_Trojan_Fakecodecs_6
{
strings:
	$a0 = { 01c889df31f6e8820000000b0000496c00009e1e00009900e7001626bc0083 }


condition:
	$a0
}