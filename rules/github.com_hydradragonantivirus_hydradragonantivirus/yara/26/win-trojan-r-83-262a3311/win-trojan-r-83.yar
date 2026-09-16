rule Win_Trojan_R_83
{
strings:
	$a0 = { f7de56b878c92d46c19353b88836904050bf1b04d1c757b8411f05481f9353b96810d1c951 }


condition:
	$a0
}