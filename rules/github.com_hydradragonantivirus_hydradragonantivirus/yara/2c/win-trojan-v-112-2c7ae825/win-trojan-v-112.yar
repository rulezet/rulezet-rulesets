rule Win_Trojan_V_112
{
strings:
	$a0 = { 8cfb0fa4bcf74f0d61c451df5f7c86c49ef22445b09a8cf74d0da4a3f74f0d61c451df5fa7434f8c }


condition:
	$a0
}