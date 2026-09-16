rule Win_Trojan_Vicking_1
{
strings:
	$a0 = { b96905e800005f80750a??9047e2f8 }


condition:
	$a0
}