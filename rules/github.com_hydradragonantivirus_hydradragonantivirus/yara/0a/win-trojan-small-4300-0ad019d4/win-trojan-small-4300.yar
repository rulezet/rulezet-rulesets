rule Win_Trojan_Small_4300
{
strings:
	$a0 = { 60e8590000006aff6a01e837000000e880000000 }


condition:
	$a0
}