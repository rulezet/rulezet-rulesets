rule Win_Trojan_Delf_753
{
strings:
	$a0 = { e864c5ffffe897bfffff6a008d8520fdffff8b4dfcba10694000e8f6d5ffff8b8520fdffffe89fd7ffff50e805e4ffff }


condition:
	$a0
}