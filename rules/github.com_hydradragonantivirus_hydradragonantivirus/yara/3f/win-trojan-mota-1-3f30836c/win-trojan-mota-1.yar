rule Win_Trojan_Mota_1
{
strings:
	$a0 = { 050055a600000200ffff5c030000e2010000040000005c03 }


condition:
	$a0
}