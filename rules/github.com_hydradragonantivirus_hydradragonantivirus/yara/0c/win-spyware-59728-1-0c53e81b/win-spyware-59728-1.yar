rule Win_Spyware_59728_1
{
strings:
	$a0 = { 558bec81c4c8feffff60837d0c010f854901 }

	$a1 = { 504f53545f55524c31 }


condition:
	$a0 and $a1
}