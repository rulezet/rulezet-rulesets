rule Win_Trojan_W_49
{
strings:
	$a0 = { 6a0459ac5033d2240374113c0274073c03740742eb064242eb02b203ff049358c0c802e2df }


condition:
	$a0
}