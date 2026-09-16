rule Win_Trojan_4_2
{
strings:
	$a0 = { 068bf00593008bd88cc88ed8bf00018b47fc89058a }


condition:
	$a0
}