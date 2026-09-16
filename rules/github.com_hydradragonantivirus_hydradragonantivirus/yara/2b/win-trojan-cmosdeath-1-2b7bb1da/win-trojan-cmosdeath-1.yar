rule Win_Trojan_CmosDeath_1
{
strings:
	$a0 = { 6b00e323e82900e83d00c606430000bb0002b80103e81000724d33dbb90100b600b80103e80100 }


condition:
	$a0
}