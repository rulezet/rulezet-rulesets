rule Win_Trojan_MLTI_2
{
strings:
	$a0 = { 05b8000150c383fce072f62ec747 }


condition:
	$a0
}