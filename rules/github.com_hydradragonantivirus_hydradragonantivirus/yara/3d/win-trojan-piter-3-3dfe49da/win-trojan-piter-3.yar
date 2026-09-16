rule Win_Trojan_Piter_3
{
strings:
	$a0 = { e800005e81ee2a00c3e8f4ff0e1f2e8c841c00b4f5cd213d9319740db8500003c650b8700003c650c30e1f8b9c1c0053 }


condition:
	$a0
}