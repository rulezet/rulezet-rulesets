rule Win_Trojan_Bero_4
{
strings:
	$a0 = { b04033c905000140054e0040cd21501e51591f58b42080c41580c40afec4b91a00bab102cd21 }


condition:
	$a0
}