rule Win_Trojan_Hupigon_1442
{
strings:
	$a0 = { 6872ca5400e8d50000008d475039 }


condition:
	$a0
}