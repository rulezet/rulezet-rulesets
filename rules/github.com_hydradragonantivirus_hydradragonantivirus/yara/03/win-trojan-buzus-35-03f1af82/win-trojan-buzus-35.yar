rule Win_Trojan_Buzus_35
{
strings:
	$a0 = { 558bec6aff68b050400068981b400064a100000000506489250000000083ec58 }


condition:
	$a0
}