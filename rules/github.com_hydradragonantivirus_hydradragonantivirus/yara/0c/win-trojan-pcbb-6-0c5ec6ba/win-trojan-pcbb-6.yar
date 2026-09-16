rule Win_Trojan_PCBB_6
{
strings:
	$a0 = { e80000b9db0889e581460012005e468074ff6ee2f9 }


condition:
	$a0
}