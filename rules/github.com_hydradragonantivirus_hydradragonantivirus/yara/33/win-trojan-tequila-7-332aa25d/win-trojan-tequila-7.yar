rule Win_Trojan_Tequila_7
{
strings:
	$a0 = { 8ccb8edbfcbb0600fcbf660985edb9600939e985e88a1584e300174743fc81ffa609720585e9bf6609fc89c6e2e7 }


condition:
	$a0
}