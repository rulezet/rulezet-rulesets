rule Win_Trojan_Hiperion_1
{
strings:
	$a0 = { 80fc4b7513065351561e525533ede80f005d5a1f5e59 }


condition:
	$a0
}