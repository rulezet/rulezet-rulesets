rule Win_Trojan_Fellowship_3
{
strings:
	$a0 = { 0650ea0000000033c08ed88f0600008f060200fb }


condition:
	$a0
}