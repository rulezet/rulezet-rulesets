rule Win_Trojan_MacGyver_6
{
strings:
	$a0 = { 0300b104d3eb8cc803c350b8ae0150cb33c08ed8803ed0040074610e1fa10300803e9a0100753731061b003106 }


condition:
	$a0
}