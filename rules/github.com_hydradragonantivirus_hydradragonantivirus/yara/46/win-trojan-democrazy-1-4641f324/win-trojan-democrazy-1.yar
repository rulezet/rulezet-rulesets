rule Win_Trojan_DemoCrazy_1
{
strings:
	$a0 = { b610012e8b86d201b957002e31044646e2f9c30000e8e7ffb4408d960501b9e100cd21e8d9ffc3 }


condition:
	$a0
}