rule Win_Trojan_Riot_6
{
strings:
	$a0 = { cd2180fa017403eb1f90fab40299b90001cd26eb0190b003b90007ba00008e9d99008b5d55 }


condition:
	$a0
}