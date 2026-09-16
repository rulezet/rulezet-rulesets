rule Win_Trojan_N_18
{
strings:
	$a0 = { 8d16ead5f881d7f5834d4689e181f7959affc62994feff81eaa8a2fc85ed7de4 }


condition:
	$a0
}