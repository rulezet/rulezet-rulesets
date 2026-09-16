rule Win_Trojan_Nostardamus_13
{
strings:
	$a0 = { 9d2f13947a12cfd1f5736022c122e4ae2bd1d44adcfd99562472a19c3195db1c2f223b4c29149c891fc5 }


condition:
	$a0
}