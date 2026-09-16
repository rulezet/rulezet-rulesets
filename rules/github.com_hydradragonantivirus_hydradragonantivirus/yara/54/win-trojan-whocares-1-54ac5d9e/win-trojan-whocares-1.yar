rule Win_Trojan_Whocares_1
{
strings:
	$a0 = { af01e81b008bf581eeb500bf000157b9b500c64600f3c64601a4c64602c3 }


condition:
	$a0
}