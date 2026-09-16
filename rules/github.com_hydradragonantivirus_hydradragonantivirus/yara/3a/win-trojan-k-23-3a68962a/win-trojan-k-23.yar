rule Win_Trojan_K_23
{
strings:
	$a0 = { 01a008032ea20101a009032ea20201b90001bb00002e }


condition:
	$a0
}