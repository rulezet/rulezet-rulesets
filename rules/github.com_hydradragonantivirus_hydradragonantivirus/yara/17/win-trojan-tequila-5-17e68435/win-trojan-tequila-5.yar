rule Win_Trojan_Tequila_5
{
strings:
	$a0 = { 05028b0e307c418b16327ccd13cb }


condition:
	$a0
}