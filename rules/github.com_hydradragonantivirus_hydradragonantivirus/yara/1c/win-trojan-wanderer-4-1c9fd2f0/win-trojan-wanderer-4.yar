rule Win_Trojan_Wanderer_4
{
strings:
	$a0 = { 4b7503e9630080fc4e742f80fc4f742ae9cf00204173 }


condition:
	$a0
}