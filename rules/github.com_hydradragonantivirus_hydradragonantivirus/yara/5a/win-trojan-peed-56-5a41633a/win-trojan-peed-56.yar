rule Win_Trojan_Peed_56
{
strings:
	$a0 = { e81100000050bb0000004089d0f7e3d1e089c258eb5d5929db8b6c1c1c81edffff000005 }


condition:
	$a0
}