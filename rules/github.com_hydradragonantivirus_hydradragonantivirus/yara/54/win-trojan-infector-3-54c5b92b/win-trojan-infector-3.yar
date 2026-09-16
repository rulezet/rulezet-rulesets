rule Win_Trojan_Infector_3
{
strings:
	$a0 = { 01a0d4022ea20101a0d5022ea20201b90001bb00002e }


condition:
	$a0
}