rule Win_Trojan_Jerusalem_7
{
strings:
	$a0 = { e0f98bd783c203b8004b061f0e07bb46001e065053 }


condition:
	$a0
}