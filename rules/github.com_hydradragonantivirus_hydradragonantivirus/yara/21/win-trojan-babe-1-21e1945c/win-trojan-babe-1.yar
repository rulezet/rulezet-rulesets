rule Win_Trojan_Babe_1
{
strings:
	$a0 = { 2cbbb0b0b9bebacd2181fbbeba754b81f9b0b075452e83 }


condition:
	$a0
}