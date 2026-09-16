rule Win_Trojan_Waledac_27
{
strings:
	$a0 = { 558bec668be44a4633da03fa8d4b245383eb5c68f9fc44 }


condition:
	$a0
}