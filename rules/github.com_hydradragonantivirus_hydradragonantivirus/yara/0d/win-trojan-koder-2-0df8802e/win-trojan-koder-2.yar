rule Win_Trojan_Koder_2
{
strings:
	$a0 = { 803e00005a750ac60600004db05aeb03[1-10]fc33ffaab80800abb88000abb853 }


condition:
	$a0
}