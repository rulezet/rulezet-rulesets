rule Win_Trojan_Archiver_1
{
strings:
	$a0 = { 601e06e800005e83ee06b8cdabcd213dbadc74718cd8488ed88b1e030083eb65b44acd21725fb82135cd21b865258bd3061fcd21b448bb6400cd2172488ec0488ed8 }


condition:
	$a0
}