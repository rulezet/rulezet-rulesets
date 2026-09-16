rule Win_Trojan_Phantom_5
{
strings:
	$a0 = { c3b440e80d00c3b43ee80700c3b43fe80100 }


condition:
	$a0
}