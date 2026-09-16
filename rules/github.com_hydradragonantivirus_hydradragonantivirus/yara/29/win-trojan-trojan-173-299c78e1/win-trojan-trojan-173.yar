rule Win_Trojan_Trojan_173
{
strings:
	$a0 = { dedecd2180fc417423b844008ec0bf00018bf7b9 }


condition:
	$a0
}