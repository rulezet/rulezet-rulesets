rule Win_Trojan_Blood_1
{
strings:
	$a0 = { 1e0e1fb419cd2150b202b40ecd21b41a }


condition:
	$a0
}