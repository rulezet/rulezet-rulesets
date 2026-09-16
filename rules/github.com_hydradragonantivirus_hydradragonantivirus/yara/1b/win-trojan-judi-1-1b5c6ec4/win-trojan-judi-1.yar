rule Win_Trojan_Judi_1
{
strings:
	$a0 = { 061e0e505350060e1f1e07be300003f08bfeb9b803b4ccfcac32c4aae2f9 }


condition:
	$a0
}