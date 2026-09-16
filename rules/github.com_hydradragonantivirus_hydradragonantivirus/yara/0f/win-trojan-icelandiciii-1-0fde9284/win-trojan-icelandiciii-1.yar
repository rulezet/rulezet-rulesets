rule Win_Trojan_IcelandicIII_1
{
strings:
	$a0 = { c6066f020a9050535152561e8bda43 }


condition:
	$a0
}