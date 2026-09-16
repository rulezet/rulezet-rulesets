rule Win_Trojan_Quarter_1
{
strings:
	$a0 = { 9c5b895e16874610d0ec731b33c08ed8a16d04258f17750fe8b7008ec3b81103e8a800fec6 }


condition:
	$a0
}