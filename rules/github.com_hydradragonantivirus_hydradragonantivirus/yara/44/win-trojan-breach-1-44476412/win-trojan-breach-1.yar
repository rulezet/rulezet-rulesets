rule Win_Trojan_Breach_1
{
strings:
	$a0 = { 446973636f6e6e6563740000ffffffff16000000422e522e452e412e432e4820436c69656e7420342e350000ffffff }


condition:
	$a0
}