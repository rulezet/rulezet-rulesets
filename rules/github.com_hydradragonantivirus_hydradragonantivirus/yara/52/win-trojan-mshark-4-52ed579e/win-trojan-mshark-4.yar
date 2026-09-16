rule Win_Trojan_Mshark_4
{
strings:
	$a0 = { b8023d03d6cd2172358bd8b43fb9 }


condition:
	$a0
}