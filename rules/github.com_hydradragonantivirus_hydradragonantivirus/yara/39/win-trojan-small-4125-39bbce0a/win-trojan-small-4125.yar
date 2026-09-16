rule Win_Trojan_Small_4125
{
strings:
	$a0 = { bd0b????34e82c000000be??00dc??c1c6108b760831c0505050505050 }


condition:
	$a0
}