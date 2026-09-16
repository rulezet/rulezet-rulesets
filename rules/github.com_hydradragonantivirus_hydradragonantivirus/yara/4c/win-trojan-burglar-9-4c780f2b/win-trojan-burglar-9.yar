rule Win_Trojan_Burglar_9
{
strings:
	$a0 = { b440cd21b000e83700ba6d03b91800b440cd21b42ccd2180f90b7521be0c03b800b08ed833 }


condition:
	$a0
}