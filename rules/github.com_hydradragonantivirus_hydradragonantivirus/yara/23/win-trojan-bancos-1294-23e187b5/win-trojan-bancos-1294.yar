rule Win_Trojan_Bancos_1294
{
strings:
	$a0 = { 156aae5fc994f91fab51a54e9efdc833ede5e113825bce7cda2153ed57918ab23f27b40d409d176ec84c39455c8f58cbede7b1d7f44c90686f3a63aeb31984abec91a50b62b0d474fb8782c3e5edf725fe1d }


condition:
	$a0
}