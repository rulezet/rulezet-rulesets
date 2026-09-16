rule Win_Trojan_XIV_2
{
strings:
	$a0 = { f280e63f7520b280b90400bb00308ec333dbb80202cd13730833c08bd0cd13ebe5ea500000 }


condition:
	$a0
}