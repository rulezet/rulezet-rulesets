rule Win_Trojan_Agent_35174
{
strings:
	$a0 = { 9cc1c932fdf7d6e8000000005b8bfb81eb9a100100415381c72c000000fc6800000000578bce87c681c369fd0000 }


condition:
	$a0
}