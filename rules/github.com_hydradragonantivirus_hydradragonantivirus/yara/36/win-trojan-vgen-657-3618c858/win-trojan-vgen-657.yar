rule Win_Trojan_VGEN_657
{
strings:
	$a0 = { 8cd3153300facc8bec8b6efafb4d4d061efcb84344cd213d3e3a75311f078cc00510002e01864800cc2e03864a00fa }


condition:
	$a0
}