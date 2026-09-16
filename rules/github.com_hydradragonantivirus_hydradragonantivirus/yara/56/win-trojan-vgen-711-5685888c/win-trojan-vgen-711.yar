rule Win_Trojan_VGEN_711
{
strings:
	$a0 = { 4d4b202f2054726964656e54205de800005e83ee13bf0001fce823050e0e1f07b430cd213c04721c3dadde7417b8 }


condition:
	$a0
}