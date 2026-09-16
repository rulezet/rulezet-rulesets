rule Win_Trojan_Bupt_1
{
strings:
	$a0 = { b80203b9010033dbba8000cd604e5633c9b404cd1a81f99419721e80fa0175190e07bed403 }


condition:
	$a0
}