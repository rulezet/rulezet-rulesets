rule Win_Spyware_11299_1
{
strings:
	$a0 = { 606880b200006800104000685c684200e8 }


condition:
	$a0
}