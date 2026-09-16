rule Win_Trojan_VGEN_730
{
strings:
	$a0 = { 025151b93401ad33062d01abe2f8b40fcd10b400cd10b409ba4701cd21b80008cd21b409ba2f01cd21cd20ac06 }


condition:
	$a0
}