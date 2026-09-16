rule Win_Trojan_Bille_1
{
strings:
	$a0 = { a0a2abefee21209320a2a0e120afaeefa2a8abe1ef20afaea2eba920a2a8e0e3e1202242696c6c }


condition:
	$a0
}