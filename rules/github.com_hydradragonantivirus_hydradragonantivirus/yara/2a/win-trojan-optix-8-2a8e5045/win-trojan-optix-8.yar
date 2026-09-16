rule Win_Trojan_Optix_8
{
strings:
	$a0 = { 69782b4c69746500ffffffff0e0000002b69732b6f6e6c696e65212530410000ffffffff110000004d792b495041 }


condition:
	$a0
}