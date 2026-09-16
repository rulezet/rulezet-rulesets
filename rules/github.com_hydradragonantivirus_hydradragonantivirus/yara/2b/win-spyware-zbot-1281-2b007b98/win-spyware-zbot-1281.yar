rule Win_Spyware_Zbot_1281
{
strings:
	$a0 = { e8????????eb038be55dc3 }


condition:
	$a0
}