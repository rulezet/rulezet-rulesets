rule Win_Trojan_MutaGen_2
{
strings:
	$a0 = { 4094711de138b8f5746477a7c31589b8baafdafe6d0ec185eca3dac3669c609475ae74a8923eb954 }


condition:
	$a0
}