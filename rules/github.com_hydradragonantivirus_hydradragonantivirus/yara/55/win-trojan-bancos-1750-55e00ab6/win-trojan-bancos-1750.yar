rule Win_Trojan_Bancos_1750
{
strings:
	$a0 = { fdf0e3c6888e38519c0fa87113285b79432f20a3c820dbed7df8d1108e7f870ea7e3d20c5bdae9618ce96e36f74d5662630d2a8457e1e405bbd90c886bb2fda2b2695ab7d986 }


condition:
	$a0
}