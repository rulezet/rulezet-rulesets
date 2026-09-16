rule Win_Trojan_Fakealert_121
{
strings:
	$a0 = { e8390000000000510000b8caad4c68000043000000294a }


condition:
	$a0
}