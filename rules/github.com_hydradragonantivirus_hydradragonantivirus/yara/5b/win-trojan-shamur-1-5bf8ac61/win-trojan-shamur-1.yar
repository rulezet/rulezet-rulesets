rule Win_Trojan_Shamur_1
{
strings:
	$a0 = { 4e63e66044e4c1656425276bef2d6664032db12071656c75736483eca3 }


condition:
	$a0
}