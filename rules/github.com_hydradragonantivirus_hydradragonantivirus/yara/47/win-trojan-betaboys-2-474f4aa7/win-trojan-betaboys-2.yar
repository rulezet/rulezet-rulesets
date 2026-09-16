rule Win_Trojan_Betaboys_2
{
strings:
	$a0 = { 03018d9e20018d96a6013e8a8e03013bda7405300f43ebf790 }


condition:
	$a0
}