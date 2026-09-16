rule Win_Trojan_ARCV_20
{
strings:
	$a0 = { e80000589681ee19018dbc2d01b9da0280350147e2fac3 }


condition:
	$a0
}