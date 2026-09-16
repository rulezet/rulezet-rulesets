rule Win_Trojan_Rocko_1
{
strings:
	$a0 = { b600b280cd13fec5720580fd10e0ef }


condition:
	$a0
}