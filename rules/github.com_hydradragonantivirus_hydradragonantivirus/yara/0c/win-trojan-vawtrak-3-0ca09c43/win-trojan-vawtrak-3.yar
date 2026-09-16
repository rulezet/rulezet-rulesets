rule Win_Trojan_Vawtrak_3
{
strings:
	$a0 = { 453a5c72656872746a746a72773472652e706462 }

	$a1 = { 497863456a70474d7a796968704c4547695072 }

	$a2 = { 6e5655636d4470464b647a5a }


condition:
	$a0 and $a1 and $a2
}