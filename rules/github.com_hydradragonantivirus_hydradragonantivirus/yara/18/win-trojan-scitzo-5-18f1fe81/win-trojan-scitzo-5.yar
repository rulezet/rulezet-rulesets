rule Win_Trojan_Scitzo_5
{
strings:
	$a0 = { ffbe2106e2fb908cc88ed8be6f01b000b868028bc88bc18bc88134000081eefeffe2f6eb4390e81200b440b9cf04 }


condition:
	$a0
}