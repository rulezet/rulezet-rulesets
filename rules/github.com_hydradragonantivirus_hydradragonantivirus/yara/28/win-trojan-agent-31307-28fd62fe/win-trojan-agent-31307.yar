rule Win_Trojan_Agent_31307
{
strings:
	$a0 = { 6f772e6b6c6d3132332e636f6d2f73657474696e67732f0000000053554343 }


condition:
	$a0
}