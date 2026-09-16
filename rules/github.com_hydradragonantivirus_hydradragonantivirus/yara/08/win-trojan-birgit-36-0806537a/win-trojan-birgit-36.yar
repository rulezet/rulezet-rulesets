rule Win_Trojan_Birgit_36
{
strings:
	$a0 = { 01b95f012e8ab68e022e8a2732e62e882743e2f5c3 }


condition:
	$a0
}