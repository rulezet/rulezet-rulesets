rule Win_Trojan_Birgit_13
{
strings:
	$a0 = { 01b944002e8ab670012e8a2732e62e882743e2f5c3 }


condition:
	$a0
}