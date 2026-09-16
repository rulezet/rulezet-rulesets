rule Win_Trojan_VCL_25
{
strings:
	$a0 = { 018aa65f0132a65d0180ec0286c4fec0fec0f6d0abe2da }


condition:
	$a0
}