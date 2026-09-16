rule Win_Dropper_Agent_34574
{
strings:
	$a0 = { 558bec83ec548d45e450e8810100008b4de48bd18d0510d00900c1e10e03c125 }


condition:
	$a0
}