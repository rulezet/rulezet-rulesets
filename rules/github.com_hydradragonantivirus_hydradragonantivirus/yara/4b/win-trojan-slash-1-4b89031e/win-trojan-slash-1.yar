rule Win_Trojan_Slash_1
{
strings:
	$a0 = { 133d013d740580fc3d74099c2eff1e0501ca0200 }


condition:
	$a0
}