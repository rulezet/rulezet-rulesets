rule Win_Trojan_DutchTiny_1
{
strings:
	$a0 = { b43fcd21803c4d741cb002e8260097b16fb440cd21b000 }


condition:
	$a0
}