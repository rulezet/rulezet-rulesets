rule Win_Trojan_Small_5330
{
strings:
	$a0 = { 5eca81d99efc1a2cc30ddf8873b8f66ccc22f86bd216546f360d8200c5094a6aca43741cf61dff13feff32173ac7ad5c793dc09dc0b475530068ff1473b8815a6f43054745bbbd4dc8c46a17ddf8 }


condition:
	$a0
}