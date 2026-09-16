rule Win_Trojan_Small_4341
{
strings:
	$a0 = { e8??000000(e9|e8)??000000[0-255]81e801760000f7d08d3405000000008d7433008db634ff1100 }


condition:
	$a0
}