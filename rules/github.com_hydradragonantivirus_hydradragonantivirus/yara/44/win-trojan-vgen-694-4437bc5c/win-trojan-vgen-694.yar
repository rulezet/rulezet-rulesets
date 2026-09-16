rule Win_Trojan_VGEN_694
{
strings:
	$a0 = { c88ed8baf407b80009cd21b4f0cd10b00180fc76740233c0a2f3070bc0740bba3f08b80009cd21eb3290b840008ec0 }


condition:
	$a0
}