rule Win_Trojan_Philis_148
{
strings:
	$a0 = { 909090558becebbe0000 }


condition:
	$a0
}