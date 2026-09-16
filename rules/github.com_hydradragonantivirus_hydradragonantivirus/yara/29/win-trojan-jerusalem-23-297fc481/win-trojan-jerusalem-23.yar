rule Win_Trojan_Jerusalem_23
{
strings:
	$a0 = { 21b44dcd21b431ba0006b104d3ea83c210cd2132c0 }


condition:
	$a0
}