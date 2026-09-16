rule Win_Trojan_Devolve_2
{
strings:
	$a0 = { 5072696e742023312c20223c68746d6c3e3c212d2d48544d4c2f4465766f6c766520 }


condition:
	$a0
}