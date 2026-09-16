rule Win_Trojan_Probe_1
{
strings:
	$a0 = { 8ec380e1c080c901b403a05e08cd1380c6043a365d0872f02a365d08e83800403b065f087705 }


condition:
	$a0
}