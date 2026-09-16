rule Win_Trojan_VGEN_676
{
strings:
	$a0 = { 06b000b708b500b100b618b24fb707cd10b700b307b615b2051e07bdd401b91c00b413cd10b42ccd218ac29850b400 }


condition:
	$a0
}