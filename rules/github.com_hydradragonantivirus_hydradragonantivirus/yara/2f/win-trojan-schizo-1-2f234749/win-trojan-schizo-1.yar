rule Win_Trojan_Schizo_1
{
strings:
	$a0 = { 33c08ec026813e55024b747422fcbf0002be0001b98e01f3a4061fbb5302fa871e840087068600fba37f03891e7d03 }


condition:
	$a0
}