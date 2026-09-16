rule Win_Trojan_Immortal_2
{
strings:
	$a0 = { 95008cc0408ec033ffb97e080e1ff3a406b8b80050cb }


condition:
	$a0
}