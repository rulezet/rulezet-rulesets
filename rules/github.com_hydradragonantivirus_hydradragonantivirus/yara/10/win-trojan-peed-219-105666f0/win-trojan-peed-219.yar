rule Win_Trojan_Peed_219
{
strings:
	$a0 = { 93b826250300732f405cffd7ff125589e551418b7d0c66abc1c80390c1c80d66 }


condition:
	$a0
}