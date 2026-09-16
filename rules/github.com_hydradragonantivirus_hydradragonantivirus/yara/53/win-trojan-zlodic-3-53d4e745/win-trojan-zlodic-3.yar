rule Win_Trojan_Zlodic_3
{
strings:
	$a0 = { ba530132f832fc3e88ba530183c6023bf17702ebdd }


condition:
	$a0
}