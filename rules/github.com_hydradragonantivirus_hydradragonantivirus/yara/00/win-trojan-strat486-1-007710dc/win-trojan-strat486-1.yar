rule Win_Trojan_STRAT486_1
{
strings:
	$a0 = { 21508b85ce01508b8563028985ce01b440b9e6018d958b00cd21588985ce01b8004233c9ba0600 }


condition:
	$a0
}