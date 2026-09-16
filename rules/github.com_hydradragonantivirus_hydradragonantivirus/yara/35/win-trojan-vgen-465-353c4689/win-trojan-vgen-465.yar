rule Win_Trojan_VGEN_465
{
strings:
	$a0 = { e800005d81ed0b018d96dc04b41acd213ec686bf04003effb6ba04e82d003e8f86ba04071fba8000b41acd213e8b }


condition:
	$a0
}