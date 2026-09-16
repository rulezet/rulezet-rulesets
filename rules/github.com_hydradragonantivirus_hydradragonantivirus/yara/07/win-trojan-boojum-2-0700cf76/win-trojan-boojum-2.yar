rule Win_Trojan_Boojum_2
{
strings:
	$a0 = { 3d004b75105689d646803c0075fa80 }


condition:
	$a0
}