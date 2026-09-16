rule Win_Trojan_K_21
{
strings:
	$a0 = { 01a0dc022ea20101a0dd022ea20201b90001bb00002e }


condition:
	$a0
}