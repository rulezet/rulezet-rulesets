rule Win_Trojan_Diablo_3
{
strings:
	$a0 = { ba005589e5bf43080e57bfd2011e5768ff009ad00aba00e8abfae8dafbc931c09a1601ba00000000558bec1ec5 }


condition:
	$a0
}