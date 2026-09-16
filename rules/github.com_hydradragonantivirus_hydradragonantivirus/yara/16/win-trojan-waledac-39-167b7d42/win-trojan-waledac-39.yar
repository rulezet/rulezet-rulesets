rule Win_Trojan_Waledac_39
{
strings:
	$a0 = { 558becc1f80003cb83c60903f98bd95783f71568bd144a00ff1508 }


condition:
	$a0
}