rule Win_Trojan_Hybridas_1
{
strings:
	$a0 = { f0574956f015bf5cedf1e1fcd8f4f0d8f00a92e5f1d8f009f2d8f7d594aa36b676e3dcb6fc }


condition:
	$a0
}