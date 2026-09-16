rule Win_Trojan_Trojan_349
{
strings:
	$a0 = { 8d963904e8330080beae0407730ab43b8d963f04cd2173e88db66d04c6045c }


condition:
	$a0
}