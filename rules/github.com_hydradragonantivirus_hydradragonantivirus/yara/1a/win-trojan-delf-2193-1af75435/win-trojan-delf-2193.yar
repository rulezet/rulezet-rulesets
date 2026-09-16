rule Win_Trojan_Delf_2193
{
strings:
	$a0 = { 2b6e44416c2b2b50706bc896fb5bb25a7a426f58577b0bb85d827269d3e0fd3b85e436bd91cd0705e0e81305b12e988d45435b9518ed26c56eeb }


condition:
	$a0
}