rule Win_Trojan_Delf_2250
{
strings:
	$a0 = { 558becb90c0000006a006a004975f953b8887e4000e88ec5ffff33c05568fe81400064ff306489 }


condition:
	$a0
}