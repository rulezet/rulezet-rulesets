rule Win_Trojan_NewBadGuy_2
{
strings:
	$a0 = { 1780f24390b402cd219043fec990 }


condition:
	$a0
}