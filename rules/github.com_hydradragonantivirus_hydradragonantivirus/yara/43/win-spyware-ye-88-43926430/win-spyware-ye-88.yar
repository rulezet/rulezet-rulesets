rule Win_Spyware_ye_88
{
strings:
	$a0 = { 505fa66e46824f8b5793[15]559b5fb4701742741e436e58781d55 }


condition:
	$a0
}