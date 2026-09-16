rule Win_Trojan_Mgn_3
{
strings:
	$a0 = { 22013d0000740fbe3d01b97b0b0004f62e040146e2f7 }


condition:
	$a0
}