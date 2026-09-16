rule Win_Trojan_Headbug_1
{
strings:
	$a0 = { 433a5c444f535c534d4152544452562e455845 }

	$a1 = { 3d4865616465724275673d }


condition:
	$a0 and $a1
}