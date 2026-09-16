rule Win_Trojan_Indonga_4
{
strings:
	$a0 = { 43913e8edb579ce0854cbfba838b0087ff7b8df0836562aa }


condition:
	$a0
}