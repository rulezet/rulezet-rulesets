rule Win_Trojan_Acurev_670_1
{
strings:
	$a0 = { f5be260189f7b97802e80300e90a00ac32062501aae2f8 }


condition:
	$a0
}