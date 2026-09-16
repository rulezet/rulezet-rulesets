rule Win_Trojan_Agent_35399
{
strings:
	$a0 = { 558bec6aff6858134300680006430064a10000000050648925 }

	$a1 = { 4e554b4520243e }


condition:
	$a0 and $a1
}