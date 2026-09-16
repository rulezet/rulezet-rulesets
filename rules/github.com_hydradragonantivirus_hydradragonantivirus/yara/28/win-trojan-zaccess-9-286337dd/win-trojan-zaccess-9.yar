rule Win_Trojan_ZAccess_9
{
strings:
	$a0 = { 8bff558bec81c480edffff5657535081ec001000006aff6a006a006a046aff546800060000ff15984042008d5424308d }


condition:
	$a0
}