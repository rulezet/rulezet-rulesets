rule Win_Trojan_Airwalker_4
{
strings:
	$a0 = { 8d76098bfeb9ab00adcc7304abe2f9c3356d0b73f7 }


condition:
	$a0
}