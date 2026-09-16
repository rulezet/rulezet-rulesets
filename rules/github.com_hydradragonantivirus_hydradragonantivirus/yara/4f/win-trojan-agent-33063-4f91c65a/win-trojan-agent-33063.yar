rule Win_Trojan_Agent_33063
{
strings:
	$a0 = { bdfce4f4beaf981d3cf9bebe13b8d234f5ff29bf00b000221e17d320c9502cbf44a3ff4b53ef5e010f20c0c600fd84757c64f8fe7fe1ffbe5a887bf64d904b309af09fa10b10de3ac595 }


condition:
	$a0
}