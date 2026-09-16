rule Win_Trojan_Fich_V_3
{
strings:
	$a0 = { 25ba5501cd21bb3101ba3a0090b9 }


condition:
	$a0
}