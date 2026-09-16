rule Win_Trojan_WhaleMutant_1
{
strings:
	$a0 = { 07e2fa5b59eb2a5bfc53c30e1fe8f7ff81eba323b9c111 }


condition:
	$a0
}