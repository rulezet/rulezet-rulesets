rule Win_Trojan_Ash_19
{
strings:
	$a0 = { e800005d81ed0b018d9e2b01533e8a862301b9ba02300743 }


condition:
	$a0
}