rule Win_Trojan_Sadovnikov_2
{
strings:
	$a0 = { e800005e83ee06b8cdabcd213dabcd74548cd8488ed88b1e030083eb3db44acd217242b82135cd21 }


condition:
	$a0
}