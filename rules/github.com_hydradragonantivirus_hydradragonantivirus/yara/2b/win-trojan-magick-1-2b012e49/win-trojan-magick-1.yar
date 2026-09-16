rule Win_Trojan_Magick_1
{
strings:
	$a0 = { 06b430cd2180ff30743e3c03723a065848501f33f6ac345a752e834402e5834411e58e44110ee800005e1f83ee2ab9 }


condition:
	$a0
}