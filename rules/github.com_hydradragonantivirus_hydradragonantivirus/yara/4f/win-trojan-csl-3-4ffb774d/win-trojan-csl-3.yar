rule Win_Trojan_CSL_3
{
strings:
	$a0 = { 068bf00590008bd88cc88ed8bf00018b47fd89058a }


condition:
	$a0
}