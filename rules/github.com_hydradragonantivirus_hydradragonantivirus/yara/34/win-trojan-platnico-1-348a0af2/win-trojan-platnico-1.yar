rule Win_Trojan_Platnico_1
{
strings:
	$a0 = { 66696c657379732e436f707946696c652044756d6d795461672c204f7461672c20 }


condition:
	$a0
}