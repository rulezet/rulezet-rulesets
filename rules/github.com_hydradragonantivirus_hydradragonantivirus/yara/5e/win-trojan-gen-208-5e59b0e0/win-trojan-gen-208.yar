rule Win_Trojan_Gen_208
{
strings:
	$a0 = { 6178ee7d84c93bb3068bc1eb3c837aaa8bc8b108103e73f80caa0d98ac260005731c3e33c605 }


condition:
	$a0
}