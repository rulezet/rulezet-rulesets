rule Win_Trojan_Mosquito_8
{
strings:
	$a0 = { 50be68002e8a242e32263d002e8824 }


condition:
	$a0
}