rule Win_Trojan_Birgit_15
{
strings:
	$a0 = { 1801b944002e8ab674012e8a2732e62e882743e2f5c3 }


condition:
	$a0
}