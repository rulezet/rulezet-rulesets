rule Win_Trojan_Simbioz_4
{
strings:
	$a0 = { 40b94b01900e1f8bd5cd21720c2ea1f400241f04072ea3 }


condition:
	$a0
}