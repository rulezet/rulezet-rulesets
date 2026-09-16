rule Win_Trojan_Birgit_32
{
strings:
	$a0 = { 01b937012e8ab663022e8a2732e62e882743e2f5c3 }


condition:
	$a0
}