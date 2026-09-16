rule Win_Trojan_Rogue_1
{
strings:
	$a0 = { ff061f2e833d017403e8a200b8bd032bf82e8b05 }


condition:
	$a0
}