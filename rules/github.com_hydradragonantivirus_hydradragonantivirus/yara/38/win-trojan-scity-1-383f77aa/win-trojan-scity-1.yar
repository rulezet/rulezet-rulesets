rule Win_Trojan_Scity_1
{
strings:
	$a0 = { 7903881e00018a9e7a03881e01018a9e7b03881e0201b430cd21e8bf013c027d03e9c3 }


condition:
	$a0
}