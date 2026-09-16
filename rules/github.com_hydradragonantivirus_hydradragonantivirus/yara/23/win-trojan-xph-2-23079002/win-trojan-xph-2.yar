rule Win_Trojan_XPh_2
{
strings:
	$a0 = { 740580fc3d75552ec6067004018bfa477444803d00 }


condition:
	$a0
}