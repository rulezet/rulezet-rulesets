rule Win_Trojan_K_3
{
strings:
	$a0 = { c00e2800042eff061500902e813e15004b1175eb90 }


condition:
	$a0
}