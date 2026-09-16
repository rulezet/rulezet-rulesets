rule Win_Trojan_Dof_5
{
strings:
	$a0 = { 2d030095bfc00303fd2e813dc3c37416b9ab03bf2c0003 }


condition:
	$a0
}