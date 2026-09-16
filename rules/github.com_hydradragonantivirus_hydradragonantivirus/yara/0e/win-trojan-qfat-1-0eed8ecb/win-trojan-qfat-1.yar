rule Win_Trojan_QFat_1
{
strings:
	$a0 = { ce002e89163502b430cd218b2e02008b1e2c008edaa390008c068e00891e8a00892ea600e83d01c43e88008bc78bd8 }


condition:
	$a0
}