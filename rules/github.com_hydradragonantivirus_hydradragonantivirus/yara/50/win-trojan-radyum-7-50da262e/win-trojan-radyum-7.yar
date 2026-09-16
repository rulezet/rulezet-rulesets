rule Win_Trojan_Radyum_7
{
strings:
	$a0 = { d8008137311f83c302e2f790 }


condition:
	$a0
}