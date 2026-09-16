rule Win_Trojan_Bravo_2
{
strings:
	$a0 = { 03008bf8eb0a33c09c2eff1e02028bc79c2eff1e020273034e75eb86eec3 }


condition:
	$a0
}