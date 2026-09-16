rule Win_Trojan_Airwalker_3
{
strings:
	$a0 = { 8d760989f7b9ab00adcc7304abe2f9c335363273f7 }


condition:
	$a0
}