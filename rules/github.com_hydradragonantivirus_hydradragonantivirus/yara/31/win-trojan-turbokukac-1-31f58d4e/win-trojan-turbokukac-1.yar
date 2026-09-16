rule Win_Trojan_TurboKukac_1
{
strings:
	$a0 = { e38cd8488ed8a103002d4100a30300 }


condition:
	$a0
}