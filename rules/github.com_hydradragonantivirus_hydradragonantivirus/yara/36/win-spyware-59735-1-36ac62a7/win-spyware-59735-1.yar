rule Win_Spyware_59735_1
{
strings:
	$a0 = { 558bec81c4bcfeffff60837d0c010f85 }

	$a1 = { 504f53545f55524c31 }

	$a2 = { 484b42574c575a004e414d45 }


condition:
	$a0 and $a1 and $a2
}