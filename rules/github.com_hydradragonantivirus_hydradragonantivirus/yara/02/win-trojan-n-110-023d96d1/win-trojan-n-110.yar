rule Win_Trojan_N_110
{
strings:
	$a0 = { e800005dbe170001eeb9a50289f78bdd81eb0601ac30d8aa }


condition:
	$a0
}