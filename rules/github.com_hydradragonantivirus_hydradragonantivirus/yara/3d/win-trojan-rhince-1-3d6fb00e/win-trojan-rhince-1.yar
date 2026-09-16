rule Win_Trojan_Rhince_1
{
strings:
	$a0 = { 01b82135cd21e800005d3d3521745a899e91008c869300b430cd213c04724a0e07b44abbffff50cd215881eb0d12 }


condition:
	$a0
}