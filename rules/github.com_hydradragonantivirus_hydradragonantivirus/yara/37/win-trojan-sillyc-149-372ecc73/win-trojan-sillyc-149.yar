rule Win_Trojan_SillyC_149
{
strings:
	$a0 = { 8db60401bfbcfcb90f01fcf3a4bed9fce848ffb440babcfcb90f01cd21b80042e82600b440b903 }


condition:
	$a0
}