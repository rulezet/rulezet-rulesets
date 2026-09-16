rule Win_Trojan_Kate_1
{
strings:
	$a0 = { 50e80000b84d99cd215d81ed0c013c4b744d1e16068cd8488ed88b1e0300b44a83eb2690cd21b448bb2500cd21 }


condition:
	$a0
}