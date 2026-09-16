rule Win_Trojan_Gen_1
{
strings:
	$a0 = { 0e07b91100f3a4be2e01b91722ac32c2f6daaae2f85b5f07b440b9282290ba8123e804fcc3 }


condition:
	$a0
}