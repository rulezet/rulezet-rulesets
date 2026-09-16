rule Win_Trojan_Crypted_295
{
strings:
	$a0 = { b8????4?005064ff35000000006489250000000033c0890850454332005cad29cfe2??50069ec39d37 }


condition:
	$a0
}