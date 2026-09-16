rule Win_Trojan_Bancos_806
{
strings:
	$a0 = { f353ce44324979e3b5befdab5400a1eed452fdc90b9a65a608b31008d8c59088bd6b1a727cbc9fd4e53d9be0f5769ab27ef7b74e46a96b61fa1a072ce6e494f1be7f16ca3799 }


condition:
	$a0
}