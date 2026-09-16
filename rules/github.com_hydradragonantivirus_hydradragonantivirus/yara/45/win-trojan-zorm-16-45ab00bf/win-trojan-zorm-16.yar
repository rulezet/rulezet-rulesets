rule Win_Trojan_Zorm_16
{
strings:
	$a0 = { 2bc393b0??02c32e8a2432e02e882446e2f5 }


condition:
	$a0
}