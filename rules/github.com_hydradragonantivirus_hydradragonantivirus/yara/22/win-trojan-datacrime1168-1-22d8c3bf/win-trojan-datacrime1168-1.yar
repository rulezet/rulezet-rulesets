rule Win_Trojan_DataCrime1168_1
{
strings:
	$a0 = { 010183ee038bc63d00007503e9fe00 }


condition:
	$a0
}