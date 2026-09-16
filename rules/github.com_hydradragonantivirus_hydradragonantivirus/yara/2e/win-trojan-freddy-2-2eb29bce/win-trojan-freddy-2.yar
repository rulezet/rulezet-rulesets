rule Win_Trojan_Freddy_2
{
strings:
	$a0 = { c0a1399a459c06d4398a519c0872bb7cba6a7f100a94f0a77b1f635936e6aa20f21fbc61ba2ea394 }


condition:
	$a0
}