rule Win_Trojan_Soupy_2
{
strings:
	$a0 = { 1001b9110281340000ade2f9 }


condition:
	$a0
}