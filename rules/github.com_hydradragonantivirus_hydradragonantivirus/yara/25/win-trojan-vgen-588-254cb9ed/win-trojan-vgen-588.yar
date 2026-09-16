rule Win_Trojan_VGEN_588
{
strings:
	$a0 = { 01beec002e812f000083c3024e75f5e800005d81ed1a011e068d96f902b41acd213ec686dc0200e82400071fba80 }


condition:
	$a0
}