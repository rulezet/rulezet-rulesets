rule Win_Trojan_Topol_1
{
strings:
	$a0 = { 4c00a800a34e0050b8730050cbc50600012ea3d6002e }


condition:
	$a0
}