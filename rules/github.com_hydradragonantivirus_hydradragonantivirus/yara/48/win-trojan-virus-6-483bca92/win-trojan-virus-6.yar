rule Win_Trojan_Virus_6
{
strings:
	$a0 = { bc4f5e81ee0e01eb02b34f8b841f01eb024cb0b9bc018dbc3301eb02b3bf310583c702e2f9 }


condition:
	$a0
}