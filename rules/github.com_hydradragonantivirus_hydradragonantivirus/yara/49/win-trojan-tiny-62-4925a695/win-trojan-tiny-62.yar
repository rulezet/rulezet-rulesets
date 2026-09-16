rule Win_Trojan_Tiny_62
{
strings:
	$a0 = { 31c92ec46dbc06551e8ed9c42eb4078cc080fca072 }


condition:
	$a0
}