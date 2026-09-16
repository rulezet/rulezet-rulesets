rule Win_Trojan_Philis_142
{
strings:
	$a0 = { 505783c404891424535033c3 }


condition:
	$a0
}