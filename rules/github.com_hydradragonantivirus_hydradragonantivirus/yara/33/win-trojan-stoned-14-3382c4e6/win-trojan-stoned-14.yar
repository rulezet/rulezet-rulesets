rule Win_Trojan_Stoned_14
{
strings:
	$a0 = { 0400b801020e07bb000233c98bd1419c }


condition:
	$a0
}