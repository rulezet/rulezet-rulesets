rule Win_Trojan_KSV_2
{
strings:
	$a0 = { 535152061e9c2ec606530301e86aff2e8f06f702062e8f063400b82135cd218cc02ea3ef022e891ef102b9080090bf }


condition:
	$a0
}