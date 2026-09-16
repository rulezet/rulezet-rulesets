rule Win_Trojan_Buggeroo_1
{
strings:
	$a0 = { 8bfeb9????ad35????abe2f9c3e8edff }


condition:
	$a0
}