rule Win_Trojan_SillyC_204
{
strings:
	$a0 = { 1384f97e9e40c7e8498983c952546145eee5e9c93a7cb0a173ceced6e56df99eff84f8c5231e44b1 }


condition:
	$a0
}