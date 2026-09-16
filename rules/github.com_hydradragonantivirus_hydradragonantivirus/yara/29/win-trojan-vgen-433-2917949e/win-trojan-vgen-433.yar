rule Win_Trojan_VGEN_433
{
strings:
	$a0 = { 7219ba4559b801facd16bf554ebe414eb802fecd2f0e58e86000909d0e1f07beff0503f5bf5343 }


condition:
	$a0
}