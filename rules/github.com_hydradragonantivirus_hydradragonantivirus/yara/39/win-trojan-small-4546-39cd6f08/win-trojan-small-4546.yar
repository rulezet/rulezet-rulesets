rule Win_Trojan_Small_4546
{
strings:
	$a0 = { 89c5be????4200adffd001d581c5????4200e85400000050e82800000055e830000000 }


condition:
	$a0
}