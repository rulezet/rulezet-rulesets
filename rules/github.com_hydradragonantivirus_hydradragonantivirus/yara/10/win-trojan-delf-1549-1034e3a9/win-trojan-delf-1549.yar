rule Win_Trojan_Delf_1549
{
strings:
	$a0 = { 508d45d8e8cefcffff8d45d8bacc3b4000e89df5ffff8b45d8e88df6ffff50e837fbff }


condition:
	$a0
}