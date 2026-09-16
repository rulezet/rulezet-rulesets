rule Win_Trojan_Kriz_6
{
strings:
	$a0 = { 509c60e80d000000433a5c56495255532e54495200e87ced }


condition:
	$a0
}