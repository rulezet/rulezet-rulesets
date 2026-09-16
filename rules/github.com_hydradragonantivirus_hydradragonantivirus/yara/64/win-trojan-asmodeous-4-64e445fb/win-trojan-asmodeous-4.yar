rule Win_Trojan_Asmodeous_4
{
strings:
	$a0 = { f124082bc6afd4043a77a1cffd81aa1f4922546e8fc7fc9091cab0ab6ca74c8e740e5555b8c6cd66 }


condition:
	$a0
}