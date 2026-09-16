rule RC56 : hardened
{
	meta:
		author = "Ivan Kwiatkowski (@JusticeRage)"
		description = "Uses constants related to RC5 or RC6"

	strings:
		$rc6_p32 = { 63 51 E1 B7 }
		$rc6_q32 = { B9 79 37 9E }
		$rc6_p64 = { 6B 2A ED 8A 62 51 E1 B7 }
		$rc6_q64 = { 15 7C 4A 7F B9 79 37 9E }

	condition:
		2 of them
}