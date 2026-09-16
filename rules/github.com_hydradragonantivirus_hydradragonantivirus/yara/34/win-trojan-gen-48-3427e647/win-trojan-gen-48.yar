rule Win_Trojan_Gen_48
{
strings:
	$a0 = { 8b35893600018b750289360201c74514 }


condition:
	$a0
}