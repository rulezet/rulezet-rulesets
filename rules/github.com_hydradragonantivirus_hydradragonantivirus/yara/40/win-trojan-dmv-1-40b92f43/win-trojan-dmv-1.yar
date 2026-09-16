rule Win_Trojan_DMV_1
{
strings:
	$a0 = { 010100558e00000000ffff01030000ab010000030000000903 }


condition:
	$a0
}