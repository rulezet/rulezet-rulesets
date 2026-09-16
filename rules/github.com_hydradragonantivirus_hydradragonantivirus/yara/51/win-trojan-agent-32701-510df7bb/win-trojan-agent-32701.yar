rule Win_Trojan_Agent_32701
{
strings:
	$a0 = { 22b3994f6bb3fcc3d45b3b77afba8a256e74be78314e1ba28e5ab7bf558ba7fa7b59f6b55d5be4173335201ac2baf631f7f07094346333eb5b3cfef4460efa3106d1b664 }


condition:
	$a0
}