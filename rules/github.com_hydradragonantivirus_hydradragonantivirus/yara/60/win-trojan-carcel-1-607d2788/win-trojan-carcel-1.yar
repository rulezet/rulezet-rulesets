rule Win_Trojan_Carcel_1
{
strings:
	$a0 = { 2ea3727da14e00a34e032ea3747da112048bc8a0140486e048488ae8890e120488261404b1 }


condition:
	$a0
}