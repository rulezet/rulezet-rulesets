rule Win_Trojan_Necro_1
{
strings:
	$a0 = { 01acb90080f2aeb90400acae75efe2fa89 }


condition:
	$a0
}