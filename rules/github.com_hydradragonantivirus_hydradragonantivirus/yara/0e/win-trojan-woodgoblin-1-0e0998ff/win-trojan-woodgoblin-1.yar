rule Win_Trojan_WoodGoblin_1
{
strings:
	$a0 = { 3f00edef60384f73ec5c45e6d101e6a769e01a784875371d }


condition:
	$a0
}