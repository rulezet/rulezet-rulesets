rule Win_Trojan_Erec_2
{
strings:
	$a0 = { b91402b440e859ff3d14027517b90000ba0000b80042e848ffba1402b91c00b440e8 }


condition:
	$a0
}