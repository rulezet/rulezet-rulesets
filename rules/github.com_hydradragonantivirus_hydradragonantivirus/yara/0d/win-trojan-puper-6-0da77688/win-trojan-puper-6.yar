rule Win_Trojan_Puper_6
{
strings:
	$a0 = { bb78540010538d85f0fbffff5750ffd68b0d3860001083c40c6a028d85f0fbffff50e8ad010000 }


condition:
	$a0
}