rule Win_Trojan_Gen_58
{
strings:
	$a0 = { c033ff33c0b9ff7ffcf2ae26f605ff }


condition:
	$a0
}