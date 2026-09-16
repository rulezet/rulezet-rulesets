rule Win_Trojan_Dof_3
{
strings:
	$a0 = { 50bfcd0403fd512e813dc3c37416b9e604bf280003fdb2 }


condition:
	$a0
}