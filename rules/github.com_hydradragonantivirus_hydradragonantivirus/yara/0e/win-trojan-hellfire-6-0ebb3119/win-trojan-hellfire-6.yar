rule Win_Trojan_Hellfire_6
{
strings:
	$a0 = { be03018bfeb90f02ad35????abe2f9c3 }


condition:
	$a0
}