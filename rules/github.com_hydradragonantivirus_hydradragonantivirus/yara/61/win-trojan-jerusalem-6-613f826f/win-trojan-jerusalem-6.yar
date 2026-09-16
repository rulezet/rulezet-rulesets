rule Win_Trojan_Jerusalem_6
{
strings:
	$a0 = { 33c0f2af8bd783c202b8004b061f0e07bb35001e065053 }


condition:
	$a0
}