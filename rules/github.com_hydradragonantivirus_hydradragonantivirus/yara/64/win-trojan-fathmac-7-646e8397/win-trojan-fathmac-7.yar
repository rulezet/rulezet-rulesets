rule Win_Trojan_FathMac_7
{
strings:
	$a0 = { 0683e90089d281e91c0189c080c70088e4268a0289c080ed00346483e90026880280ed004683 }


condition:
	$a0
}