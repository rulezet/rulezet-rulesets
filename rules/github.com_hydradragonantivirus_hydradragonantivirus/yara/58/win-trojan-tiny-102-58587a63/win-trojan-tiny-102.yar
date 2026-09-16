rule Win_Trojan_Tiny_102
{
strings:
	$a0 = { b8023dcc930e1fbe[0-10]b43f[0-10]8bd6[0-10]cc2bc8 }


condition:
	$a0
}