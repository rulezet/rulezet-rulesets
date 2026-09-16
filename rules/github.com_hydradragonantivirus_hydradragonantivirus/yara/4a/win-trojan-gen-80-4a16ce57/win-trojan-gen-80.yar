rule Win_Trojan_Gen_80
{
strings:
	$a0 = { 35cd21895e8c8c468eb4258d945701 }


condition:
	$a0
}