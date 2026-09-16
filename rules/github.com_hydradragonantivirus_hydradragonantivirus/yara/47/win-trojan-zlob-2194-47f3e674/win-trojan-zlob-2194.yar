rule Win_Trojan_Zlob_2194
{
strings:
	$a0 = { be00000000[0-150]8d351aa94000 }


condition:
	$a0
}