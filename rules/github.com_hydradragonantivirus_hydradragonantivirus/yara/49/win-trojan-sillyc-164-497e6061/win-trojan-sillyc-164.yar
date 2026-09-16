rule Win_Trojan_SillyC_164
{
strings:
	$a0 = { 2e8b1efc0181c32c0251b104d3eb4359cd211eb448bb1600cd215050b42fcd21580653501e8ed833d2b41acd21 }


condition:
	$a0
}