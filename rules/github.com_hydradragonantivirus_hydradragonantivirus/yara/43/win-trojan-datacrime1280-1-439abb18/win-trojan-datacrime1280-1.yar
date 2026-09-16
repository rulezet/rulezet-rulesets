rule Win_Trojan_DataCrime1280_1
{
strings:
	$a0 = { 36010183ee038bc63d00007503e90201 }


condition:
	$a0
}