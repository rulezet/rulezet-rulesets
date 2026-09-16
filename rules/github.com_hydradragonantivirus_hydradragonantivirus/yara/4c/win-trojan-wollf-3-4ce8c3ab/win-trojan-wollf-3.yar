rule Win_Trojan_Wollf_3
{
strings:
	$a0 = { f90273085f[0-7]803a2275498d7a[0-13]568d6c }


condition:
	$a0
}