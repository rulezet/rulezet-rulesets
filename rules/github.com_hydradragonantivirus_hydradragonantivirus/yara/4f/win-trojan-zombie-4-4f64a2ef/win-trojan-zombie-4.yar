rule Win_Trojan_Zombie_4
{
strings:
	$a0 = { cd218cc8488ed88b3600008b3e02008b0e04008b1606008edb8ec383c31001de01d98ed189d4 }


condition:
	$a0
}