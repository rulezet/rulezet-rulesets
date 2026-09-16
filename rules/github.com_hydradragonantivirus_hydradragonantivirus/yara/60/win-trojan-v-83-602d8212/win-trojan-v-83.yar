rule Win_Trojan_V_83
{
strings:
	$a0 = { 02b440e84900721233c9b80042e83f008bd6b90300b440e835005a59b80157e82d00b43ee828 }


condition:
	$a0
}