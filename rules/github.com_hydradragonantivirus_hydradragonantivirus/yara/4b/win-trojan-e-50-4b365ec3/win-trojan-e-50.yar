rule Win_Trojan_E_50
{
strings:
	$a0 = { 6a0068400600008d95fc96ffff528b8558f1ffff50e8f5000000898598b8ffff6a0068dc0f00008d8d8c74ffff518b9558f1ffff52e8db000000 }


condition:
	$a0
}