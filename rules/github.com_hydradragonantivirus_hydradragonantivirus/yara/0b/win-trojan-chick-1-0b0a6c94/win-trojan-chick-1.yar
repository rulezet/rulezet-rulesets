rule Win_Trojan_Chick_1
{
strings:
	$a0 = { d2b90200b81103b280bb00508ec3cd13730432e4cd13fec680fe0472e4fec5ebde }


condition:
	$a0
}