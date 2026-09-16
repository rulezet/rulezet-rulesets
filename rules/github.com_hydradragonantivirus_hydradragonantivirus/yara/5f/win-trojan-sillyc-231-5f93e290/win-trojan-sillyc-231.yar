rule Win_Trojan_SillyC_231
{
strings:
	$a0 = { 568bfe03740156a5a45eb44eba5a0003d6cd21b8023dba9e00cd2193b43fb1038bd6cd21b0e838047421a29900b800 }


condition:
	$a0
}