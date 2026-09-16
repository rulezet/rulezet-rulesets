rule Win_Trojan_3APA3A_1
{
strings:
	$a0 = { e800005e83ee0456505351521e06b404cd1a80fe087512 }


condition:
	$a0
}