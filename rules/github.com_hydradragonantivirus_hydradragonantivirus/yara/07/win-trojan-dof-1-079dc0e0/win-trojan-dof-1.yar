rule Win_Trojan_Dof_1
{
strings:
	$a0 = { 90582d030095bfc10303fd2e813dc3c37416b9bc03bf2c0003 }


condition:
	$a0
}