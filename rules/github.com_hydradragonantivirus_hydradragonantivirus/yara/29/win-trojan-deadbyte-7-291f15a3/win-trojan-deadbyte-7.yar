rule Win_Trojan_DeadByte_7
{
strings:
	$a0 = { be00011e07bf00048b0e2901f3a4be2e0133c98a3c80f7cc883c46413b0e290175f1 }


condition:
	$a0
}