rule Win_Trojan_Agent_35421
{
strings:
	$a0 = { 6801907800e801000000c3c3b3d87538 }

	$a1 = { 144048454c4f }

	$a2 = { c04d4100494c2046524ff03a }


condition:
	$a0 and $a1 and $a2
}