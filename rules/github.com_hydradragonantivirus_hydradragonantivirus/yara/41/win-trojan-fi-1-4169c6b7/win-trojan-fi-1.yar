rule Win_Trojan_FI_1
{
strings:
	$a0 = { 2300d1e25f579c59a1eb04b8d700cd138b1ef10481c36a15515e534bbbe2f4538b36cd0081eb9cae53b913005e56 }


condition:
	$a0
}