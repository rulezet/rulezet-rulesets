rule Win_Trojan_Philis_90
{
strings:
	$a0 = { 565683c40489142450565ee8b800000037d5dd1d9341e6706bc93107 }


condition:
	$a0
}