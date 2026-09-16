rule Win_Trojan_Personality_3
{
strings:
	$a0 = { 3e3e20433a5c576f724461762e7662730d }

	$a1 = { 433a5c52756e645642532e5642530d0a0d0a65786974 }


condition:
	$a0 and $a1
}