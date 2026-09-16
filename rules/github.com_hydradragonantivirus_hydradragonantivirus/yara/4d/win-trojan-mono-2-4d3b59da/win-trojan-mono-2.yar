rule Win_Trojan_Mono_2
{
strings:
	$a0 = { fdf3a406e800005983c10651cb2e8c4f }


condition:
	$a0
}