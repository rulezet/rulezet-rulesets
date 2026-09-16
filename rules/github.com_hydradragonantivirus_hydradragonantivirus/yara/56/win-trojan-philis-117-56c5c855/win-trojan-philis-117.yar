rule Win_Trojan_Philis_117
{
strings:
	$a0 = { 505083c404893424535783c404e854000000dd851cda791127b78199f0c0b333c9aeed0218753e12 }


condition:
	$a0
}