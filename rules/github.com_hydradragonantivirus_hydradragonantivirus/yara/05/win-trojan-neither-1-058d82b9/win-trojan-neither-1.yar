rule Win_Trojan_Neither_1
{
strings:
	$a0 = { b90a01b440cd21b9450129ca89d6b440cd215233c98a0e }


condition:
	$a0
}