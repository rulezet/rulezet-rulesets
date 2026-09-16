rule Win_Trojan_Vacsina_TP_1
{
strings:
	$a0 = { bd00b82425cd210e1fba1400b40fcd21b800438e5e0e8b }


condition:
	$a0
}