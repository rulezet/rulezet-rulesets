rule Win_Trojan_Delf_2258
{
strings:
	$a0 = { 558becb9090000006a006a004975f953b8887e4000e88ec5ffff33c055683181 }


condition:
	$a0
}