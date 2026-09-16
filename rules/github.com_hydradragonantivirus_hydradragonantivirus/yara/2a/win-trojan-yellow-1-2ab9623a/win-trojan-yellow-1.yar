rule Win_Trojan_Yellow_1
{
strings:
	$a0 = { be5106bf00018b0ead01b80177cd218c }


condition:
	$a0
}