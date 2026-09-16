rule Win_Trojan_Gen_232
{
strings:
	$a0 = { adbbc99ef82bc370e3fde1025d95cd535dbef840e3cfedb7fe33c0a7e9de87d6b4500641bc73 }


condition:
	$a0
}