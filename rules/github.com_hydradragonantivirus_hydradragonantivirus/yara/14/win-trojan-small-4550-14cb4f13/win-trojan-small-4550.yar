rule Win_Trojan_Small_4550
{
strings:
	$a0 = { 89c5befe9f4000adffd001d581c5d88b4000e85400000050e82800000055e830000000 }


condition:
	$a0
}