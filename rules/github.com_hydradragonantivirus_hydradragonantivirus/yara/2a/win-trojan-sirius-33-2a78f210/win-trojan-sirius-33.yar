rule Win_Trojan_Sirius_33
{
strings:
	$a0 = { e80000582d0901958db62501568b96e603b960018bfead33c2d1caabe2f8c3 }


condition:
	$a0
}