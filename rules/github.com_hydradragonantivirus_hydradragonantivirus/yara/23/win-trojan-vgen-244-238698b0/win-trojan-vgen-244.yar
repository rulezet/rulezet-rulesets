rule Win_Trojan_VGEN_244
{
strings:
	$a0 = { e7009a0d0085005589e5b800049acd02e70081ec0004e819fee853fe8dbe00fe16578dbe00ff1657b80200509a }


condition:
	$a0
}