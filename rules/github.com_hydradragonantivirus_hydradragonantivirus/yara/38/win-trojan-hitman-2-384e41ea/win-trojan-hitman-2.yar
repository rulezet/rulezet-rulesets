rule Win_Trojan_Hitman_2
{
strings:
	$a0 = { 010100550000000000ffff000000003c010000060000005404 }


condition:
	$a0
}