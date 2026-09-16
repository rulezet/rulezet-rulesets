rule Win_Trojan__0366_0006_002_1
{
strings:
	$a0 = { d2b80242cd21b917008d960001b440cd2172341e8cc08ed8b9c40233d2b440cd211f722333 }


condition:
	$a0
}