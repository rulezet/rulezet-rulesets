rule Win_Trojan_EDV_4
{
strings:
	$a0 = { d8c7078118813f8118740d2d00103d00b875ecb800a8 }


condition:
	$a0
}