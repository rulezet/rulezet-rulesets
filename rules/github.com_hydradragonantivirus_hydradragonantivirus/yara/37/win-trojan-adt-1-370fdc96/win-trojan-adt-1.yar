rule Win_Trojan_ADT_1
{
strings:
	$a0 = { 0401565fb99502acd2c8f6d0aae2f8ba0301b9f206b440cd2172d1be0401e81a00c3b43fcd21c3 }


condition:
	$a0
}