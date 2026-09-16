rule Win_Trojan_Piaf_1
{
strings:
	$a0 = { 1f0e07a1e507be2b01b97d068bfe33dbfec87414ac32c4 }


condition:
	$a0
}