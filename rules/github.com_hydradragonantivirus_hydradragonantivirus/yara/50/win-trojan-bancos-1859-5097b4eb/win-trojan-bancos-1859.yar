rule Win_Trojan_Bancos_1859
{
strings:
	$a0 = { 52dc7a2cb016ec4e3bb2efbc24f66e3e9edc14c0ae24a6eb615ba60426559c31bfb269d0630b3427cc83ba9d05f0bf5d12e4cbf37726e4aa61de471e45c46ffeb3eef8ce72f3 }


condition:
	$a0
}