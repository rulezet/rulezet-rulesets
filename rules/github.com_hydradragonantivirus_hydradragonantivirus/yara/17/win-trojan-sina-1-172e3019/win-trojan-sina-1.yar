rule Win_Trojan_Sina_1
{
strings:
	$a0 = { bf0001b84bffcd2183ee030e070e1ffcb9b804f3a4b8210150c32e8c0e19022ec706170280002e8c0e1d022e8c0e21 }


condition:
	$a0
}