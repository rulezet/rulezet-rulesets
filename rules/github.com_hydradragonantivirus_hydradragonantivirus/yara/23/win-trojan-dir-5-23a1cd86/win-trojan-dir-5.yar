rule Win_Trojan_Dir_5
{
strings:
	$a0 = { e20d31c08744142e33063f0489441a2e }


condition:
	$a0
}