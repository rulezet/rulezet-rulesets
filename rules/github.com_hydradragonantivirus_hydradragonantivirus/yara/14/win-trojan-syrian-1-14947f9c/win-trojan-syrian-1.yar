rule Win_Trojan_Syrian_1
{
strings:
	$a0 = { 9c80fc4b7402eb4cb8023dcd2172458bd8505351521e0e1f }


condition:
	$a0
}