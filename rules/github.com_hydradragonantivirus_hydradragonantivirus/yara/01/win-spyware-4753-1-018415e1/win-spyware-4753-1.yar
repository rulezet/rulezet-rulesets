rule Win_Spyware_4753_1
{
strings:
	$a0 = { e80000000058eb00f95850e800000000c70424ba30181333c1eb00eb00 }


condition:
	$a0
}