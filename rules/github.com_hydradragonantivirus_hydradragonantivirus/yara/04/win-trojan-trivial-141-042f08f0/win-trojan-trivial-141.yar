rule Win_Trojan_Trivial_141
{
strings:
	$a0 = { 91b44eba1a01cd21ba9e00b8013dcd21938bd6b11eb440cd21c3 }


condition:
	$a0
}