rule Win_Trojan_Incmd_1
{
strings:
	$a0 = { 636f7079202f66202f7920433a5c4e565c494e434d4e442e45584520433a5c57494e444f57535c }


condition:
	$a0
}