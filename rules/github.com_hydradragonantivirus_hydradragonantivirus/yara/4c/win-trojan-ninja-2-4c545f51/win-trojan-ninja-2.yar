rule Win_Trojan_Ninja_2
{
strings:
	$a0 = { e800005e06b8ccfacd13073dafcc7503e990008cc0488ec026a103002d510026a30300268b1e010003d88ec30e }


condition:
	$a0
}