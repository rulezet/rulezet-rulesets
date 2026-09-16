rule Win_Trojan_Vienna_74
{
strings:
	$a0 = { 80f2aeb90400acae75ede2fa5e07897c29908bfe }


condition:
	$a0
}