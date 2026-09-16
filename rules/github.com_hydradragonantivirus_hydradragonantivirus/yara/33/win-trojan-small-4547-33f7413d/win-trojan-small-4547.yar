rule Win_Trojan_Small_4547
{
strings:
	$a0 = { b8????420089c6ad83ec10ffd089c581c5????4200e84c00000050e82000000055e8 }


condition:
	$a0
}