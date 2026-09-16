rule Win_Trojan_Remiz_1
{
strings:
	$a0 = { 494e464558545589e531c09a44023d02bf7a021e57bf180c0e579a62033d027444bf7a021e57 }


condition:
	$a0
}