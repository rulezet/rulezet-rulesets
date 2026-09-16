rule Win_Trojan_VCC_25
{
strings:
	$a0 = { 28ff13f4b75c3032867500e0bf875d30ff13862bff13bab75c300e30463a863c8030ff13d937f4b7 }


condition:
	$a0
}