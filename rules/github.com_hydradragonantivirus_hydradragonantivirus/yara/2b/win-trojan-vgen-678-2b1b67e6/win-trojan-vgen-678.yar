rule Win_Trojan_VGEN_678
{
strings:
	$a0 = { 03018db680018bfeadfec480fc3a7504fec0b430ab8db600018dbe1509b9150890ba000155e855005d51b43c8d }


condition:
	$a0
}