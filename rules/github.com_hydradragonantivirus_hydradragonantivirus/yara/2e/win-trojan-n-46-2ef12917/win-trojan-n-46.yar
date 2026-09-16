rule Win_Trojan_N_46
{
strings:
	$a0 = { 5e81ee03009c5053515257551e061e062bc08ed8b430cd2186c4c41eb2 }


condition:
	$a0
}