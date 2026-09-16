rule Win_Trojan_VGEN_402
{
strings:
	$a0 = { de23d833eb03f523d93bed03f7b8c8e12bde33eb03f523d93bed03f703f6bfc8012bde03f523d93bed03f703f61bd2 }


condition:
	$a0
}