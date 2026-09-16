rule Win_Trojan_BAT_86
{
strings:
	$a0 = { 64656c2077696e2e2a2064656c202a2e2a }

	$a1 = { 64656c74726565202a2e2a202f79 }


condition:
	$a0 and $a1
}