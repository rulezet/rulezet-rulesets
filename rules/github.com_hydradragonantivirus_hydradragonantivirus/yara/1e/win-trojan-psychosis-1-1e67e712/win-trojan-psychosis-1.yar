rule Win_Trojan_Psychosis_1
{
strings:
	$a0 = { 01033606018a24b9730483c632908bfee80700ac32c4 }


condition:
	$a0
}