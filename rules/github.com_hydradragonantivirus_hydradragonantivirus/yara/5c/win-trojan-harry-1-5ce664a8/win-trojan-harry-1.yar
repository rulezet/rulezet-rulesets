rule Win_Trojan_Harry_1
{
strings:
	$a0 = { 525259242e7377709a0000ac005589e581ec02028dbe00ff165731c0509acc06ac00bffac31e }


condition:
	$a0
}