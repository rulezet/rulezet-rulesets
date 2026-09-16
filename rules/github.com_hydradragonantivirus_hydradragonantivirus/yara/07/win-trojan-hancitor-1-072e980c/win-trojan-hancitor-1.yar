rule Win_Trojan_Hancitor_1
{
strings:
	$a0 = { b8abaaaa2af7eb8bc2c1e81f03c28d14408bc32bc203c099be3a000000f7fe8bf1908a043932c332c288043985db750388043983fe097e0433f6eb0146413b4d147c }


condition:
	$a0
}