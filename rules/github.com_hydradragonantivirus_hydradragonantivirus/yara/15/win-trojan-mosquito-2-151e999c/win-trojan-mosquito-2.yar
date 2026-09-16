rule Win_Trojan_Mosquito_2
{
strings:
	$a0 = { 50be49002e8a242e32261e002e8824 }


condition:
	$a0
}