rule Win_Trojan_Delf_471
{
strings:
	$a0 = { e805feffffa3046940008b0650e8e0fdffff68dc454000e8fefdffff890766c703020068934a0000e8cdfdffff668943026820464000e8c7fdff }


condition:
	$a0
}