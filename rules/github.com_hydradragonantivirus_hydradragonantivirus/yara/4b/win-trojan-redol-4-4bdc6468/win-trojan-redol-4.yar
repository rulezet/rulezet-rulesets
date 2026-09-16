rule Win_Trojan_Redol_4
{
strings:
	$a0 = { 6a0058bacd2eeb03ebfac383ec04c1e8158d9410????0000891424ff14246a??ff1508204000 }


condition:
	$a0
}