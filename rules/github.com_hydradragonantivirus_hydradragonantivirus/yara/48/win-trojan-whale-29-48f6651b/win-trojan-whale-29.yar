rule Win_Trojan_Whale_29
{
strings:
	$a0 = { e8290081eb9f23b9872349f949803710 }


condition:
	$a0
}