rule Win_Trojan_Hydra_9
{
strings:
	$a0 = { 3fb9ffffba9301cd210593012ea3 }


condition:
	$a0
}