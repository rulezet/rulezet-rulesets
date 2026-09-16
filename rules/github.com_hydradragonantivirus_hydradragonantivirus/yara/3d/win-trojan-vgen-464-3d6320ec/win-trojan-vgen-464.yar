rule Win_Trojan_VGEN_464
{
strings:
	$a0 = { 2689450d0e1fba340bb9020051b43fb91a00cd2159badb05e81d02e2efe8250257060e07813e }


condition:
	$a0
}