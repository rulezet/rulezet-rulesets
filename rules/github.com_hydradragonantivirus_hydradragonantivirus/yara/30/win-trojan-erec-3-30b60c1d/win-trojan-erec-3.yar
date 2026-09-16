rule Win_Trojan_Erec_3
{
strings:
	$a0 = { b96e02b440e8e1fe3d6e027517b90000ba0000b80042e8d0feba6e02b91c00b440e8 }


condition:
	$a0
}