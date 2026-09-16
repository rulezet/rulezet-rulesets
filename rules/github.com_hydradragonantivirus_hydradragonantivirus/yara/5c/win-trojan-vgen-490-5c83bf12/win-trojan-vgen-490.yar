rule Win_Trojan_VGEN_490
{
strings:
	$a0 = { cd21b43b8d95b100cd21e80d00b43b8d56c0cd218be55dc35c0055b42fcd21538bec81ec8000 }


condition:
	$a0
}