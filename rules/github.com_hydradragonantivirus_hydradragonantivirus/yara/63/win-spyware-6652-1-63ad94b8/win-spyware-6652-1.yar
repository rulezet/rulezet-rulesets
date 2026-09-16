rule Win_Spyware_6652_1
{
strings:
	$a0 = { 505783c4045081c8897f3a4cf7d058f7 }


condition:
	$a0
}