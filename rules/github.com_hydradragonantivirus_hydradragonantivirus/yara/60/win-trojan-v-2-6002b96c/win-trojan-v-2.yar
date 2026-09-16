rule Win_Trojan_V_2
{
strings:
	$a0 = { 020e1fba0000b440e859fe7233b00033c933d2e877ffba67000e1fb90300b440e841fe721b81 }


condition:
	$a0
}