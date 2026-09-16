rule Win_Trojan_AntiEnter_2
{
strings:
	$a0 = { 861800aa6a0258cd17eb0590b402cd1ae2ec }


condition:
	$a0
}