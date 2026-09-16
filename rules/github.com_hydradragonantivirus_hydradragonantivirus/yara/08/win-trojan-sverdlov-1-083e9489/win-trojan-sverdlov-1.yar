rule Win_Trojan_Sverdlov_1
{
strings:
	$a0 = { 2d0003fe2e300547e2fae800005e83ee }


condition:
	$a0
}