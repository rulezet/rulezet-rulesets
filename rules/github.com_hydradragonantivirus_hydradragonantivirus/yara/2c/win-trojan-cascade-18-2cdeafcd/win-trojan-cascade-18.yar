rule Win_Trojan_Cascade_18
{
strings:
	$a0 = { e80000fa5b81eb30012ef6872a0101bc8506740c8dbf4d01313d3125474c75f8 }


condition:
	$a0
}