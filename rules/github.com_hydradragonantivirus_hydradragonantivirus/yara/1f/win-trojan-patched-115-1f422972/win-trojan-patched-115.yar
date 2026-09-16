rule Win_Trojan_Patched_115
{
strings:
	$a0 = { e8000000005d81ed46??44008b0424250000ffff81384d5a900074072d00100000ebf1 }


condition:
	$a0
}