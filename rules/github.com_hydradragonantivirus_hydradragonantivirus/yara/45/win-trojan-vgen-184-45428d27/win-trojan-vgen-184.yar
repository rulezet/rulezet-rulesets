rule Win_Trojan_VGEN_184
{
strings:
	$a0 = { c88ec0b8c0078ed8b80005cd10be0001b40e8a043c24740dbb0000b90100cd10463c2475ebb400cd16b40fcd10b400 }


condition:
	$a0
}