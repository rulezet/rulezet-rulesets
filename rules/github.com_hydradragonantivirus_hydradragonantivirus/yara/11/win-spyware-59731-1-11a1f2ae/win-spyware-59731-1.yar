rule Win_Spyware_59731_1
{
strings:
	$a0 = { 558bec81c4d8feffff60837d0c010f85 }

	$a1 = { 504f53545f55524c31 }

	$a2 = { 534f554c0052455f4e414d45 }


condition:
	$a0 and $a1 and $a2
}