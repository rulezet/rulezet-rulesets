rule Win_Trojan_Popwin_41
{
strings:
	$a0 = { 2b5ae6592b21b4d8f657ce22f1664befdbea3a5eb1e1e19ca2b4193343dd5919de2a145754c8280a4322621394c3aa2d }


condition:
	$a0
}