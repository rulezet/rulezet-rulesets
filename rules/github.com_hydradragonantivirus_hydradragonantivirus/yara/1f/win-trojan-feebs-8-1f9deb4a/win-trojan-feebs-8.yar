rule Win_Trojan_Feebs_8
{
strings:
	$a0 = { 3e6576616c28756e65736361706528 }

	$a1 = { 3d25 }

	$a2 = { 2229293b[0-2]28223c }


condition:
	$a0 and $a1 and $a2
}