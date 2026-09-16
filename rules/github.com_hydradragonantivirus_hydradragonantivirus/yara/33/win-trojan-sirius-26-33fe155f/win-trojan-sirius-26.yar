rule Win_Trojan_Sirius_26
{
strings:
	$a0 = { 582d0901958db62301568b966802b9a2008bfead33c2abe2fac3 }


condition:
	$a0
}