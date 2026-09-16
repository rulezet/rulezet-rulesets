rule Win_Trojan_OnlineGames_37
{
strings:
	$a0 = { f9602d18050000f91bc3e800000000f90bc133f6f5e808000000e90700000083f8 }

	$a1 = { df35674f764f4a0a }


condition:
	$a0 and $a1
}