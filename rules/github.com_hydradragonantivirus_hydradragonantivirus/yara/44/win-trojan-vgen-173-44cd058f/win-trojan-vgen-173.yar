rule Win_Trojan_VGEN_173
{
strings:
	$a0 = { 4a012e89163502b430cd218b2e02008b1e2c008edaa390008c068e00891e8a00892ea600e83d01c43e88008bc78bd8 }


condition:
	$a0
}