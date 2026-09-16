rule Win_Trojan_Italian_8
{
strings:
	$a0 = { 9e1301b9b9012e8ab6e4022e8a2732e62e882743e2f5c3 }


condition:
	$a0
}