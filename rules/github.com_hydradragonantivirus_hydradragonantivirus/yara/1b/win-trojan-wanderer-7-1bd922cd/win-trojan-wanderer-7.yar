rule Win_Trojan_Wanderer_7
{
strings:
	$a0 = { 5033c08ed88e1e6a04813e9200dcac7464b44abbffffcd2181eb1b10725780c710b44acd21b448bb1a00cd217247 }


condition:
	$a0
}