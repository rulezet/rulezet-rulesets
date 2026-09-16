rule Win_Trojan_Corrupted_63
{
strings:
	$a0 = { 90e800000000[0-18]2300000000008089 }


condition:
	$a0
}