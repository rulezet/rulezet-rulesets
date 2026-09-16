rule Win_Trojan_Hymn_3
{
strings:
	$a0 = { 64f50007e800005e83ee4cfc2e81bc }


condition:
	$a0
}