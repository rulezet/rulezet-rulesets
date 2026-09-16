rule Win_Trojan_Crypt_187
{
strings:
	$a0 = { fc68b412e87af968dc752829f831c99bfcbff80300f8f8c1c7062c00fc9084ed6862423a6f9b5efc8d }


condition:
	$a0
}