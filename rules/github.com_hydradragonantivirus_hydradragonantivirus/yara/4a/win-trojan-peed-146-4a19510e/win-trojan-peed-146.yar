rule Win_Trojan_Peed_146
{
strings:
	$a0 = { e8c3000000bf00??a8e1bb89ebffff81c36e14000001c789f89681c382600e0081eb79600e0058b8e53e0000e8730000 }


condition:
	$a0
}