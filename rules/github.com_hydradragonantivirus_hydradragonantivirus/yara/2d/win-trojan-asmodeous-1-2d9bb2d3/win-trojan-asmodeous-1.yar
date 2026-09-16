rule Win_Trojan_Asmodeous_1
{
strings:
	$a0 = { 580527008bde81c386048bcb2bc8e80200eb0b2e8a072e3047014be2f6c383eb368bcb2bce }


condition:
	$a0
}