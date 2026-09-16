rule Win_Trojan_Redarc_1
{
strings:
	$a0 = { c63e04fb8bfe5733c9fc90adc1c8ff9093adc1c0ff9086e04186fb9041ab41939041ab81f94305 }


condition:
	$a0
}