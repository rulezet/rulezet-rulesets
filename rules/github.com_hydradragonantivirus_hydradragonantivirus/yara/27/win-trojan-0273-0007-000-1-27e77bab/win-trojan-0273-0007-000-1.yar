rule Win_Trojan__0273_0007_000_1
{
strings:
	$a0 = { 803e9efeb47417b002e81e00a30601b440cd2132c0e812008bd7b440cd21b43ecd21b44febc757 }


condition:
	$a0
}