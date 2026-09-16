rule Win_Trojan_Packed_128
{
strings:
	$a0 = { eb065652554c5a0090 }


condition:
	$a0
}