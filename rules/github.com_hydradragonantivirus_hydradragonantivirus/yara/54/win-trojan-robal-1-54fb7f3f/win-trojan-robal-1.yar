rule Win_Trojan_Robal_1
{
strings:
	$a0 = { d853060ae01e0e591e90583bc1750e565e2e8b36010181c6ff0083c60481c63f0056b98b075b }


condition:
	$a0
}