rule Win_Trojan_Saddam_3
{
strings:
	$a0 = { b900008cca8edabaf902cd6b7237a1e4 }


condition:
	$a0
}