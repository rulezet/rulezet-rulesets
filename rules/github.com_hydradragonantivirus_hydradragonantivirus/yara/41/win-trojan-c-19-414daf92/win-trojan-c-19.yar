rule Win_Trojan_C_19
{
strings:
	$a0 = { 8b2e0001bcfeff81ed0b01e80200eb273e8b8640018db64201b9ef0031044646e2fac3e8ea }


condition:
	$a0
}