rule Win_Trojan_Sirius_27
{
strings:
	$a0 = { e80000582d0901958db62301568b967e02b9ad008bfead33c2abe2fac3 }


condition:
	$a0
}