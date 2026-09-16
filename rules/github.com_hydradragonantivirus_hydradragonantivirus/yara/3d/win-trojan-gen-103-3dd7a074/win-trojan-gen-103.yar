rule Win_Trojan_Gen_103
{
strings:
	$a0 = { 58072eff2e0500813e12004d5a7406 }


condition:
	$a0
}