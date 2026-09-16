rule Win_Trojan_Multiflu_1
{
strings:
	$a0 = { b82125cd210e07e87eff0e1fb42acd2180fa017509b002b9700299cd269de94bffcd12eb0e }


condition:
	$a0
}