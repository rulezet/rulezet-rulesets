rule Win_Trojan_F_37
{
strings:
	$a0 = { 255c1fb9e6f5b2d081c10f13eb0f1a131a131a131a131a131a131a131a0097c3a843eb }


condition:
	$a0
}