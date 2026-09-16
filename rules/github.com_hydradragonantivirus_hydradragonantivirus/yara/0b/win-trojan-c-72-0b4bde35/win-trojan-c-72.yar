rule Win_Trojan_C_72
{
strings:
	$a0 = { ff010100550002000100ffff0f0d00005a160000030000006403 }


condition:
	$a0
}