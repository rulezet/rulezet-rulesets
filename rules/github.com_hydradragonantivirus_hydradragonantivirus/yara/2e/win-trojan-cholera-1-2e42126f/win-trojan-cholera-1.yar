rule Win_Trojan_Cholera_1
{
strings:
	$a0 = { 515256571e069c3dfefe74083d004b7411eb31909d07 }


condition:
	$a0
}