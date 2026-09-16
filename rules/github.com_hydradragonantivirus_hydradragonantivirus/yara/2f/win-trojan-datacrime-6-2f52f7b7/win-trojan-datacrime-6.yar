rule Win_Trojan_Datacrime_6
{
strings:
	$a0 = { 8cea068d9c38012bcbfa2e8a072ec6 }


condition:
	$a0
}