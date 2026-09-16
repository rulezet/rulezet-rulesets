rule Win_Trojan_Sdbot_96
{
strings:
	$a0 = { 558bec6aff68e0714000681660400064a100000000506489250000000083ec68 }


condition:
	$a0
}