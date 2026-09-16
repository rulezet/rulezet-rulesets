rule Win_Trojan_Aprilfool_1
{
strings:
	$a0 = { 9635028db60f00b9100131144646e2fac3 }


condition:
	$a0
}