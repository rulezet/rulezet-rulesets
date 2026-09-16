rule Win_Trojan_Riot_29
{
strings:
	$a0 = { fa1f7d02ebc3a03204e80d00803e32041974b6fe063204e2edb405b500b6008a163204cd13 }


condition:
	$a0
}