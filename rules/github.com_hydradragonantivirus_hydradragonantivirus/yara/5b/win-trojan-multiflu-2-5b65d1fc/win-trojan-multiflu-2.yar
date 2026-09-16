rule Win_Trojan_Multiflu_2
{
strings:
	$a0 = { 85ffb82125cd210e07e87bff0e1fb42acd2180fa017509b002b9700299cd269de947ffcd12eb0f }


condition:
	$a0
}