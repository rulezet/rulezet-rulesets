rule Win_Trojan_Vgen_116
{
strings:
	$a0 = { 90b8004ccd21e2f61e060e0e1f07e800005d81ed14008db6a5008bfeb94402e80300e91802acf6d8d0c8d0c8d0 }


condition:
	$a0
}