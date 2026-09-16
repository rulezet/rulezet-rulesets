rule Win_Trojan_Birgit_40
{
strings:
	$a0 = { 01b983012e8ab6b5022e8a2732e62e882743e2f5c3 }


condition:
	$a0
}