rule Win_Trojan_Small_4134
{
strings:
	$a0 = { e82a000000be3f????0081f62636f200e80700000075ee50871c24c38b3650 }


condition:
	$a0
}