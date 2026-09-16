rule Win_Trojan_Stoned_11
{
strings:
	$a0 = { b801022e8a16410080fa807506b90e00eb0490b90300b601cd1372de32e4cd1a8bc2b9060033 }


condition:
	$a0
}