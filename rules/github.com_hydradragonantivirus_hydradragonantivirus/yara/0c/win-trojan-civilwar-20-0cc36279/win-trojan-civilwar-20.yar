rule Win_Trojan_CivilWar_20
{
strings:
	$a0 = { e12f80f90159744a51523e8b9ef401b43fb903008d96ee }


condition:
	$a0
}