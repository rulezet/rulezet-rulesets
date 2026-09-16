rule Win_Trojan_VGEN_16
{
strings:
	$a0 = { 66032e89165a02b430cd218b2e02008b1e2c008edaa37d008c067b00891e7700892e9100e84e01c43e75008bc78bd8 }


condition:
	$a0
}