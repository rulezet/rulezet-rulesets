rule Win_Trojan_Shan_1
{
strings:
	$a0 = { 83c0138bf08bfeb91f070000ac34b2aae2fa }


condition:
	$a0
}