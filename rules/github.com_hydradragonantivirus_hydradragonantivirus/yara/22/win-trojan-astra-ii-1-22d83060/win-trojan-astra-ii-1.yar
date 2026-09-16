rule Win_Trojan_Astra_II_1
{
strings:
	$a0 = { 06535657fa8cc88ed88ec0be5e0003f58bfeb9b1028bddfcad33873f00abe2f85f5e5b071fc3 }


condition:
	$a0
}