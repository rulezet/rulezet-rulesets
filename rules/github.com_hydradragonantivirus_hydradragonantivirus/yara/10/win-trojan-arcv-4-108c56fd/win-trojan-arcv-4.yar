rule Win_Trojan_ARCV_4
{
strings:
	$a0 = { e80000582d120196e8 }

	$a1 = { 8dbc1d01b9a8028035??47e2fac3 }


condition:
	$a0 and $a1
}