rule Win_Trojan_PFS_1
{
strings:
	$a0 = { 8fe75be053e557ef5d67e75ee4e72af4e15f68e6b72c }


condition:
	$a0
}