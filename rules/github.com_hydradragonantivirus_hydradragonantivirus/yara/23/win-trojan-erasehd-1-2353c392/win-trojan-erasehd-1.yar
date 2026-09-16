rule Win_Trojan_EraseHD_1
{
strings:
	$a0 = { 95002e8916c701b430cd218b2e02008b1e2c008edaa37d008c067b00891e7700892e9100c7068100ffffe80101c43e }


condition:
	$a0
}