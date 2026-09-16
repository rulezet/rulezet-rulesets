rule Win_Trojan_Agent_35611
{
strings:
	$a0 = { 5056575283ca3653510f8551feffff661b379d2a }

	$a1 = { 6b726e6c2e666e72 }

	$a2 = { c53241235333c423f2335224 }


condition:
	$a0 and $a1 and $a2
}