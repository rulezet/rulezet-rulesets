rule Win_Trojan_Toast_1
{
strings:
	$a0 = { e800005d81ed03010e1fe8 }

	$a1 = { 3e8b96????8db60d01b9980231144646e2fa }


condition:
	$a0 and $a1
}