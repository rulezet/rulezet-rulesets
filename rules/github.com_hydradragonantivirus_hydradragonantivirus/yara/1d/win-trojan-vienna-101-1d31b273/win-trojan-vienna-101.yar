rule Win_Trojan_Vienna_101
{
strings:
	$a0 = { 80f2aeb90400acae75ede2fa5e07897c2d908bfe }


condition:
	$a0
}