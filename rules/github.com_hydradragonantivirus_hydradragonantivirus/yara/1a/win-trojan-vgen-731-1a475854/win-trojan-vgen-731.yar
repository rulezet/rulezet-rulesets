rule Win_Trojan_VGEN_731
{
strings:
	$a0 = { e80000cc5d81ed0701fe8ec101bf0001578db6b701a5a550501f1e5b39d874082ec6060001c358c30e1fb41aba00fecd }


condition:
	$a0
}