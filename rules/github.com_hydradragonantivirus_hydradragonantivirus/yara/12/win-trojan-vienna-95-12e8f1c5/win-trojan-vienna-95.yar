rule Win_Trojan_Vienna_95
{
strings:
	$a0 = { e1feba1f0003d6cd21ba1f00b8023d03d6cd217306eb35eb31eb478bd8b80057cd21b42c89 }


condition:
	$a0
}