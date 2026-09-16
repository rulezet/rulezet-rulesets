rule Win_Trojan_HappyMonday_2
{
strings:
	$a0 = { 4e43280053504f4c125355434b4552532e0500200e5020 }


condition:
	$a0
}