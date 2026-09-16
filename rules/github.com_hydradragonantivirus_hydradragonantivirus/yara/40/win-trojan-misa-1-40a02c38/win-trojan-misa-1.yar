rule Win_Trojan_Misa_1
{
strings:
	$a0 = { 32f6b22032ffcd10e800005db4090e1fba0e0003d5cd21ebe1596f752061726520696e666563 }


condition:
	$a0
}