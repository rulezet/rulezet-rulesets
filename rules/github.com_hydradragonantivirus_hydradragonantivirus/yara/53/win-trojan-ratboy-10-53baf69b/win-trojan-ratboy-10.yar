rule Win_Trojan_Ratboy_10
{
strings:
	$a0 = { 3e8b860c018db63f01b97c0031044646e2fac3 }


condition:
	$a0
}