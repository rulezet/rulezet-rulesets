rule Win_Trojan_Minimal_15
{
strings:
	$a0 = { 010100550001000000ffff000000000e010000060000000903 }


condition:
	$a0
}