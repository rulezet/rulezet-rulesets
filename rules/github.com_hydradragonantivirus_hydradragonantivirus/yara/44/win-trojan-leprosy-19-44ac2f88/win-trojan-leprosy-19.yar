rule Win_Trojan_Leprosy_19
{
strings:
	$a0 = { e9eb002ebb3001b930158a2732260601882743e2f5c38b1eee0153e8 }


condition:
	$a0
}