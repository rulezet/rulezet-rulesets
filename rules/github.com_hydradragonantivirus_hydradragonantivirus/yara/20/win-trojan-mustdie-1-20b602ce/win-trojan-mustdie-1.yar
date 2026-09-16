rule Win_Trojan_MustDie_1
{
strings:
	$a0 = { c3ba0001b9b704b440e80bfec3b8024233c933d2e8 }


condition:
	$a0
}