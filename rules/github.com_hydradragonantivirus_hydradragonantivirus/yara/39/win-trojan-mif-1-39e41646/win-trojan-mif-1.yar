rule Win_Trojan_Mif_1
{
strings:
	$a0 = { d3ff8d960401b9cc01b440cd21e8c5ffc3 }


condition:
	$a0
}