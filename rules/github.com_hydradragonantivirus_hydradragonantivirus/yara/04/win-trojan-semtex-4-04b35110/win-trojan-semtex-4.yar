rule Win_Trojan_Semtex_4
{
strings:
	$a0 = { 8ec0268b3e8400268b1686008ec226813d9c507503e9eb00bafffffc0e1f8bf581c6bc00 }


condition:
	$a0
}