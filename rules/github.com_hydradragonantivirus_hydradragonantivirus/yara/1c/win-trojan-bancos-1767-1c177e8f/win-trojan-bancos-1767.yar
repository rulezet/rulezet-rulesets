rule Win_Trojan_Bancos_1767
{
strings:
	$a0 = { f30d8db2db0c1c680fd0de5f59f4553784a37d9856856e7d20852aa4cba85b14e79db18d944b2e2097a4f5eda3670fc72a49bbc1d54a55b517d0e44da46d11ffc5b57046abd1 }


condition:
	$a0
}