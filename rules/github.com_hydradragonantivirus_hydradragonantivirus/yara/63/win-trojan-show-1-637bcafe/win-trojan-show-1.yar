rule Win_Trojan_Show_1
{
strings:
	$a0 = { 8cca2e89168102b430cd218b2e02008b1e2c008edaa31d1e8c061b1e891e171e892e331ec706211effffe80501c43e }


condition:
	$a0
}