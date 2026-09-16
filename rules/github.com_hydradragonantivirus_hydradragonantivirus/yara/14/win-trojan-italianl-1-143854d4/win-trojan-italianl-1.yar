rule Win_Trojan_Italianl_1
{
strings:
	$a0 = { 9e1801b96e022e8ab69e032e8a2732e62e882743e2f5c3 }


condition:
	$a0
}