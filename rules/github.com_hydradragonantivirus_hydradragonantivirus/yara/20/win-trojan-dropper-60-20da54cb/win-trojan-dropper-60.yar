rule Win_Trojan_Dropper_60
{
strings:
	$a0 = { 30706f78623d22e2eb746acb6a6a6a216a6a6a2b6c2b6c6a6a2ba26a6a6a6a6a }


condition:
	$a0
}