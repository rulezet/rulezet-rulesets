rule Win_Trojan_CrazyEddie_2
{
strings:
	$a0 = { 7404813c5a4dc380fc02740f80fc03 }


condition:
	$a0
}