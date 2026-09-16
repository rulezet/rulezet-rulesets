rule Win_Trojan_Qhost_143
{
strings:
	$a0 = { 558bec6aff68d020400068c016400064a100000000506489250000000083ec68 }


condition:
	$a0
}