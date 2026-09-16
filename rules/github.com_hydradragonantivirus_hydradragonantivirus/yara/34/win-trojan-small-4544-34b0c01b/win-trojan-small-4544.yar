rule Win_Trojan_Small_4544
{
strings:
	$a0 = { b9????4?008b396a00ffd79581c5fa????00e8 }


condition:
	$a0
}