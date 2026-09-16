rule Win_Trojan_Kode_2
{
strings:
	$a0 = { 568b740156bf00018db49301a4a55eb44e8d948a01cd217303eb6790b8023dba9e00cd217303eb5a9093b43f }


condition:
	$a0
}