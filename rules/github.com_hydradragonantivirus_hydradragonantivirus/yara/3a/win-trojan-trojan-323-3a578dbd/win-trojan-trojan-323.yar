rule Win_Trojan_Trojan_323
{
strings:
	$a0 = { acb90080f2aeb90400acae75ede2fa5e07897c4e908bfe }


condition:
	$a0
}